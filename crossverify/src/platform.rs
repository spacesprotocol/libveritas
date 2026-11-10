//! Platforms an account can be claimed on, and how accounts are written in
//! a record.
//!
//! A claim is a SIP-7 record keyed by the platform (`x`, `github`, ...)
//! whose first value names the account. Nacho accepts several spellings
//! there (`@alice`, profile URLs), so [`Platform::normalize_username`] turns
//! all of them into one canonical form. Signing and verifying both go
//! through it, so a notary proof made for `Alice` verifies against a claim
//! written as `https://x.com/alice`.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Platform {
    X = 1,
    Instagram = 2,
    Telegram = 3,
    GitHub = 4,
    Bluesky = 5,
    Mastodon = 6,
    HackerNews = 7,
    Website = 8,
    Nostr = 9,
}

impl Platform {
    pub const ALL: [Platform; 9] = [
        Platform::X,
        Platform::Instagram,
        Platform::Telegram,
        Platform::GitHub,
        Platform::Bluesky,
        Platform::Mastodon,
        Platform::HackerNews,
        Platform::Website,
        Platform::Nostr,
    ];

    /// The record key the claim is stored under.
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::X => "x",
            Platform::Instagram => "instagram",
            Platform::Telegram => "telegram",
            Platform::GitHub => "github",
            Platform::Bluesky => "bluesky",
            Platform::Mastodon => "mastodon",
            Platform::HackerNews => "hackernews",
            Platform::Website => "website",
            Platform::Nostr => "nostr",
        }
    }

    /// Parse a record key. Only the exact key ([`Platform::as_str`]) counts:
    /// no aliases, no case folding.
    pub fn parse(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == key)
    }

    /// Whether clients check this platform themselves. Notary proofs are
    /// never accepted for these: falling back to a notary snapshot would let
    /// a revoked link (handle removed from the bio) or a blocked request
    /// (forced "unavailable") downgrade the check to a stale attestation.
    /// Only Telegram and Instagram, which have no keyless way to check, use
    /// notary proofs.
    pub fn is_self_checked(self) -> bool {
        !matches!(self, Platform::Telegram | Platform::Instagram)
    }

    /// Canonical account from what a user typed or a record holds. Returns
    /// `None` for anything that isn't a valid account on the platform. The
    /// result only contains characters safe to put in a URL.
    ///
    /// | Platform | Accepts | Canonical |
    /// |---|---|---|
    /// | X, Instagram, Telegram, GitHub | `alice`, `@Alice`, `x.com/alice` | `alice` |
    /// | Bluesky | `@alice.bsky.social`, `bsky.app/profile/alice.bsky.social` | `alice.bsky.social` |
    /// | Mastodon | `@alice@mastodon.social`, `https://mastodon.social/@alice` | `alice@mastodon.social` |
    /// | Hacker News | `pg`, `news.ycombinator.com/user?id=pg` | `pg` (case kept) |
    /// | Website | `example.com`, `https://example.com/about` | `https://example.com` |
    /// | Nostr | `npub1…`, 64-char hex | `npub1…` |
    pub fn normalize_username(self, raw: &str) -> Option<String> {
        let s = raw.trim();
        match self {
            Platform::X | Platform::Instagram | Platform::Telegram | Platform::GitHub => {
                self.simple_username(s)
            }
            Platform::Bluesky => bluesky_handle(s),
            Platform::Mastodon => mastodon_account(s),
            Platform::HackerNews => hackernews_user(s),
            Platform::Website => website_origin(s),
            Platform::Nostr => crate::nostr::normalize_npub(s),
        }
    }

    fn simple_username(self, s: &str) -> Option<String> {
        let s = match self.username_from_url(s) {
            Some(u) => u,
            None => s.strip_prefix('@').unwrap_or(s),
        };
        let valid = match self {
            Platform::X => chars_ok(s, 1, 15, b"_"),
            Platform::Instagram => {
                chars_ok(s, 1, 30, b"_.") && !s.starts_with('.') && !s.ends_with('.')
            }
            // 5-32 normally; collectible usernames can be 4.
            Platform::Telegram => chars_ok(s, 4, 32, b"_"),
            // Older accounts can have trailing or doubled hyphens.
            Platform::GitHub => chars_ok(s, 1, 39, b"-") && !s.starts_with('-'),
            _ => false,
        };
        valid.then(|| s.to_ascii_lowercase())
    }

    /// `Some(segment)` when `s` looks like a URL: the first path segment if
    /// the host belongs to this platform, otherwise `Some("")`, which then
    /// fails validation. `None` when `s` isn't a URL.
    fn username_from_url(self, s: &str) -> Option<&str> {
        if !s.contains('/') {
            return None;
        }
        let hosts: &[&str] = match self {
            Platform::X => &["x.com", "twitter.com"],
            Platform::Instagram => &["instagram.com"],
            Platform::Telegram => &["t.me", "telegram.me"],
            Platform::GitHub => &["github.com"],
            _ => &[],
        };
        let (host, path) = split_host(s);
        if !hosts.iter().any(|h| host.eq_ignore_ascii_case(h)) {
            return Some("");
        }
        let seg = path.split(['/', '?', '#']).next().unwrap_or_default();
        Some(seg.strip_prefix('@').unwrap_or(seg))
    }

    /// Link a person can open to check the account themselves. `account` is
    /// in canonical form.
    pub fn profile_url(self, account: &str) -> String {
        match self {
            Platform::X => format!("https://x.com/{account}"),
            Platform::Instagram => format!("https://www.instagram.com/{account}/"),
            Platform::Telegram => format!("https://t.me/{account}"),
            Platform::GitHub => format!("https://github.com/{account}"),
            Platform::Bluesky => format!("https://bsky.app/profile/{account}"),
            Platform::Mastodon => match account.split_once('@') {
                Some((user, server)) => format!("https://{server}/@{user}"),
                None => account.to_string(),
            },
            Platform::HackerNews => format!("https://news.ycombinator.com/user?id={account}"),
            Platform::Website => account.to_string(),
            Platform::Nostr => format!("https://njump.me/{account}"),
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

fn chars_ok(s: &str, min: usize, max: usize, extra: &[u8]) -> bool {
    (min..=max).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

/// Split `[scheme://][www.|mobile.]host/path` into host and path.
fn split_host(s: &str) -> (&str, &str) {
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let rest = rest
        .strip_prefix("www.")
        .or_else(|| rest.strip_prefix("mobile."))
        .unwrap_or(rest);
    rest.split_once('/').unwrap_or((rest, ""))
}

/// A DNS name: at least two labels of `a-z 0-9 -`, no leading or trailing
/// hyphen. Expects lowercase input.
pub(crate) fn is_domain(s: &str) -> bool {
    s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

fn bluesky_handle(s: &str) -> Option<String> {
    let h = if s.contains('/') {
        let (host, path) = split_host(s);
        if !host.eq_ignore_ascii_case("bsky.app") {
            return None;
        }
        let rest = path.strip_prefix("profile/")?;
        rest.split(['/', '?', '#']).next().unwrap_or_default()
    } else {
        s.strip_prefix('@').unwrap_or(s)
    };
    let h = h.to_ascii_lowercase();
    is_domain(&h).then_some(h)
}

fn mastodon_account(s: &str) -> Option<String> {
    let (user, server) = if s.contains('/') {
        // `https://mastodon.social/@alice`. No `www.` stripping: the host
        // is the server.
        let rest = s
            .strip_prefix("https://")
            .or_else(|| s.strip_prefix("http://"))
            .unwrap_or(s);
        let (server, path) = rest.split_once('/')?;
        let seg = path.split(['/', '?', '#']).next()?;
        (seg.strip_prefix('@')?.to_string(), server.to_string())
    } else {
        let s = s.strip_prefix('@').unwrap_or(s);
        let (u, srv) = s.split_once('@')?;
        (u.to_string(), srv.to_string())
    };
    let server = server.to_ascii_lowercase();
    (chars_ok(&user, 1, 30, b"_") && is_domain(&server))
        .then(|| format!("{}@{server}", user.to_ascii_lowercase()))
}

fn hackernews_user(s: &str) -> Option<String> {
    let u = if s.contains("ycombinator.com") {
        // `news.ycombinator.com/user?id=pg`
        let query = s.split_once('?')?.1;
        let query = query.split('#').next().unwrap_or_default();
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix("id="))?
            .to_string()
    } else {
        s.strip_prefix('@').unwrap_or(s).to_string()
    };
    // Usernames are case-sensitive on HN: `PG` isn't `pg`.
    chars_ok(&u, 2, 15, b"_-").then_some(u)
}

fn website_origin(s: &str) -> Option<String> {
    let (scheme, host, port) = parse_origin(s, true)?;
    // Only HTTPS is fetched: the site's TLS certificate is the proof.
    Some(match port {
        Some(p) if scheme == "https" => format!("https://{host}:{p}"),
        _ => format!("https://{host}"),
    })
}

/// `scheme`, `host` and non-default `port` of an http(s) URL. Strict on
/// purpose: the host must be a plain lowercase-able DNS name and anything
/// else in the authority (userinfo, `\`, `%`, IP literals, unicode) is
/// rejected rather than interpreted. With `bare`, a missing scheme means
/// `https`.
fn parse_origin(s: &str, bare: bool) -> Option<(&'static str, String, Option<u16>)> {
    let lower = s.trim().to_ascii_lowercase();
    let (scheme, rest) = if let Some(r) = lower.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = lower.strip_prefix("http://") {
        ("http", r)
    } else if bare && !lower.contains("://") {
        ("https", lower.as_str())
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            (h, Some(p.parse::<u16>().ok()?))
        }
        None => (authority, None),
    };
    // No TLD is all digits, so this also rules out IPv4 literals.
    let tld = host.rsplit('.').next().unwrap_or_default();
    if !is_domain(host) || tld.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let default = if scheme == "https" { 443 } else { 80 };
    Some((scheme, host.to_string(), port.filter(|&p| p != default)))
}

/// Whether `url` (a final URL reported by the HTTP client) is on the HTTPS
/// origin `origin` (from [`Platform::normalize_username`] for a website).
pub(crate) fn same_https_origin(url: &str, origin: &str) -> bool {
    match (parse_origin(url, false), parse_origin(origin, false)) {
        (Some(a), Some(b)) => a.0 == "https" && a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_keys_are_exact() {
        for key in [
            "twitter", "gh", "hn", "bsky", "tg", "ig", "url", "web", "npub", "GitHub", " x",
            "proof:x",
        ] {
            assert_eq!(Platform::parse(key), None, "{key}");
        }
        for p in Platform::ALL {
            assert_eq!(Platform::parse(p.as_str()), Some(p));
        }
    }

    #[test]
    fn usernames_from_text_and_urls() {
        let x = Platform::X;
        for raw in [
            "alice",
            "@Alice",
            " alice ",
            "x.com/alice",
            "https://x.com/Alice",
            "https://www.twitter.com/alice?s=20",
            "http://mobile.x.com/alice/status/1",
        ] {
            assert_eq!(
                x.normalize_username(raw).as_deref(),
                Some("alice"),
                "{raw:?}"
            );
        }
        assert_eq!(x.normalize_username("_buffrr").as_deref(), Some("_buffrr"));
        for raw in [
            "",
            "@",
            "alice/../x",
            "evil.com/alice",
            "a".repeat(16).as_str(),
            "al ice",
        ] {
            assert_eq!(x.normalize_username(raw), None, "{raw:?}");
        }
        assert_eq!(
            Platform::GitHub
                .normalize_username("https://github.com/Buffrr")
                .as_deref(),
            Some("buffrr")
        );
        assert_eq!(
            Platform::Instagram
                .normalize_username("instagram.com/alice.coffee/")
                .as_deref(),
            Some("alice.coffee")
        );
        assert_eq!(
            Platform::Telegram
                .normalize_username("t.me/Buffrr")
                .as_deref(),
            Some("buffrr")
        );
    }

    #[test]
    fn only_telegram_and_instagram_use_notaries() {
        let notary: Vec<_> = Platform::ALL
            .into_iter()
            .filter(|p| !p.is_self_checked())
            .collect();
        assert_eq!(notary, vec![Platform::Instagram, Platform::Telegram]);
    }

    #[test]
    fn per_platform_rules() {
        assert_eq!(Platform::Instagram.normalize_username("a){id}"), None);
        assert_eq!(Platform::Instagram.normalize_username(".alice"), None);
        assert_eq!(Platform::GitHub.normalize_username("-alice"), None);
        assert_eq!(Platform::GitHub.normalize_username("a_b"), None);
        assert_eq!(Platform::GitHub.normalize_username(&"a".repeat(40)), None);
        assert_eq!(Platform::Telegram.normalize_username("abc"), None);
    }

    #[test]
    fn bluesky_mastodon_hackernews() {
        let b = Platform::Bluesky;
        for raw in [
            "@Alice.bsky.social",
            "alice.bsky.social",
            "https://bsky.app/profile/alice.bsky.social",
        ] {
            assert_eq!(
                b.normalize_username(raw).as_deref(),
                Some("alice.bsky.social"),
                "{raw}"
            );
        }
        assert_eq!(b.normalize_username("alice"), None);
        assert_eq!(
            b.normalize_username("evil.com/profile/alice.bsky.social"),
            None
        );

        let m = Platform::Mastodon;
        for raw in [
            "@Gargron@mastodon.social",
            "gargron@mastodon.social",
            "https://mastodon.social/@Gargron",
        ] {
            assert_eq!(
                m.normalize_username(raw).as_deref(),
                Some("gargron@mastodon.social"),
                "{raw}"
            );
        }
        assert_eq!(m.normalize_username("gargron"), None);
        assert_eq!(
            m.profile_url("gargron@mastodon.social"),
            "https://mastodon.social/@gargron"
        );

        let hn = Platform::HackerNews;
        assert_eq!(hn.normalize_username("pg").as_deref(), Some("pg"));
        assert_eq!(hn.normalize_username("PG").as_deref(), Some("PG"));
        assert_eq!(
            hn.normalize_username("https://news.ycombinator.com/user?id=dang")
                .as_deref(),
            Some("dang")
        );
        assert_eq!(hn.normalize_username("a"), None);
    }

    #[test]
    fn website_origins() {
        let w = Platform::Website;
        for raw in [
            "buffrr.dev",
            "https://buffrr.dev",
            "https://Buffrr.dev/about?x=1",
            "http://buffrr.dev/",
        ] {
            assert_eq!(
                w.normalize_username(raw).as_deref(),
                Some("https://buffrr.dev"),
                "{raw}"
            );
        }
        assert_eq!(
            w.normalize_username("https://buffrr.dev:8443").as_deref(),
            Some("https://buffrr.dev:8443")
        );
        assert_eq!(w.normalize_username("ftp://buffrr.dev"), None);
        assert_eq!(w.normalize_username("https://user@buffrr.dev"), None);
        assert_eq!(w.normalize_username("localhost"), None);
        assert_eq!(
            w.normalize_username("https://buffrr.dev:443/x").as_deref(),
            Some("https://buffrr.dev")
        );
        for bad in [
            "https://evil.com\\@buffrr.dev",
            "https://buffrr.dev@evil.com",
            "https://127.0.0.1",
            "https://[::1]",
            "https://münchen.de",
            "https://buffrr.dev:",
            "https://buffrr.dev:99999",
            "https://buffrr.dev:+80",
            "https://%62uffrr.dev",
            "javascript://buffrr.dev",
        ] {
            assert_eq!(w.normalize_username(bad), None, "{bad}");
        }
        assert_eq!(
            w.normalize_username("xn--mnchen-3ya.de").as_deref(),
            Some("https://xn--mnchen-3ya.de")
        );
    }

    #[test]
    fn redirect_origins() {
        let o = "https://buffrr.dev";
        for ok in [
            "https://buffrr.dev/.well-known/spaces.txt",
            "https://BUFFRR.dev/x",
            "https://buffrr.dev:443/x",
            "https://buffrr.dev?x",
        ] {
            assert!(same_https_origin(ok, o), "{ok}");
        }
        for bad in [
            "http://buffrr.dev/.well-known/spaces.txt",
            "https://www.buffrr.dev/x",
            "https://buffrr.dev.evil.com/x",
            "https://buffrr.dev:8443/x",
            "https://evil.com/buffrr.dev",
            "https://buffrr.dev@evil.com/",
            "",
        ] {
            assert!(!same_https_origin(bad, o), "{bad}");
        }
        assert!(same_https_origin(
            "https://buffrr.dev:8443/x",
            "https://buffrr.dev:8443"
        ));
    }
}
