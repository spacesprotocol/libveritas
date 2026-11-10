//! Checking a claim, without doing any I/O.
//!
//! [`Check`] is a step machine. It asks for one HTTP request or one relay
//! query at a time; the caller performs it and hands back the result, until
//! the check is done. The same code runs natively, in React Native and in
//! the browser, each with its own `fetch`.
//!
//! ```ignore
//! let claim = Claim::new("github", &["buffrr", "id:41967894"])?;
//! let mut check = Check::new(&claim, "buffrr@bitcoin", &Context::default())?;
//! let mut step = check.start();
//! let outcome = loop {
//!     step = match step {
//!         Step::Fetch(req) => check.on_response(http_get(&req)),
//!         Step::Query(q) => check.on_events(query_relays(&q)),
//!         Step::Done(outcome) => break outcome,
//!     };
//! };
//! ```
//!
//! Notary proofs only count on platforms with no direct check (Telegram,
//! Instagram). Elsewhere they're ignored, so a blocked request or a revoked
//! link can't downgrade a check to a stale attestation
//! ([`Platform::is_self_checked`]).

use crate::claim::{Claim, Proof};
use crate::matching::{post_claims, profile_mentions, text_mentions};
use crate::notary::{self, NotaryProof, Source};
use crate::{Handle, HandleError, Platform, html, nostr};
use serde::Deserialize;
use std::fmt;

/// Responses larger than this are rejected.
pub const MAX_BODY: usize = 256 * 1024;
/// Size limit for a website's `/.well-known/spaces.txt`.
pub const MAX_WELL_KNOWN: usize = 16 * 1024;

/// What a check needs from the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// x-only keys of the notaries this client trusts.
    pub trusted_notaries: Vec<[u8; 32]>,
    /// Relays to ask for Nostr profiles, besides the claim's own hints.
    pub nostr_relays: Vec<String>,
    /// Optional GitHub token, for servers that check many accounts (60
    /// requests/hour per IP without one). Never ship one in an app.
    pub github_token: Option<String>,
}

impl Default for Context {
    fn default() -> Self {
        Context {
            trusted_notaries: vec![],
            nostr_relays: vec!["wss://purplepag.es".into(), "wss://relay.damus.io".into()],
            github_token: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// An HTTP GET for the caller to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub url: String,
    pub headers: Vec<Header>,
}

/// What the caller got back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// Final URL, after any redirects the caller followed.
    pub url: String,
    pub body: Vec<u8>,
}

/// A Nostr relay query for the caller to perform: send
/// `["REQ", <id>, <filter>]` to each relay over WebSocket and collect the
/// `EVENT` payloads until `EOSE` or a timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayQuery {
    pub relays: Vec<String>,
    /// A NIP-01 filter, as JSON.
    pub filter: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Fetch(Request),
    Query(RelayQuery),
    Done(Outcome),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Verified(Verified),
    Failed(Failure),
    /// Couldn't tell: network error, rate limit, platform down. Try later.
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub platform: Platform,
    /// Canonical account. For Bluesky, the account's current handle.
    pub account: String,
    pub source: Source,
    pub via: Via,
    /// Stable platform ID when known (GitHub, Bluesky DID, Mastodon,
    /// notary).
    pub account_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// Checked against the platform directly.
    Platform,
    /// A trusted notary's signed attestation.
    Notary { key: [u8; 32], issued_at: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The claim has no proof this crate can check.
    NoProof,
    /// The account, post or file doesn't exist (or is private).
    NotFound,
    /// The proof points at a different account than the claim, e.g. the
    /// username now belongs to someone else, or a tweet by another author.
    AccountMismatch {
        found: String,
    },
    /// The account exists but doesn't point back at the handle.
    HandleNotFound,
    BadResponse(String),
    BadNotaryProof(notary::Error),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::NoProof => write!(f, "no proof to check"),
            Failure::NotFound => write!(f, "not found"),
            Failure::AccountMismatch { found } => write!(f, "belongs to another account ({found})"),
            Failure::HandleNotFound => write!(f, "the account doesn't point back at the handle"),
            Failure::BadResponse(m) => write!(f, "unexpected response: {m}"),
            Failure::BadNotaryProof(e) => write!(f, "notary proof: {e}"),
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Verified(v) => {
                write!(
                    f,
                    "verified: {} {} (found in {}",
                    v.platform, v.account, v.source
                )?;
                match v.via {
                    Via::Platform => write!(f, ", checked directly)"),
                    Via::Notary { key, .. } => {
                        write!(f, ", notary {})", &nostr::hex(&key)[..16])
                    }
                }
            }
            Outcome::Failed(e) => write!(f, "failed: {e}"),
            Outcome::Unavailable(m) => write!(f, "unavailable: {m}"),
        }
    }
}

#[derive(Debug, Clone)]
enum Method {
    GitHub(u64),
    Tweet(u64),
    Bluesky(String),
    Mastodon,
    HackerNews,
    Website,
    Nostr,
    Notary(NotaryProof),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Idle,
    Waiting,
    GitHubLinks,
}

pub struct Check {
    handle: Handle,
    claim: Claim,
    ctx: Context,
    methods: Vec<Method>,
    current: usize,
    stage: Stage,
    results: Vec<Outcome>,
}

enum Next {
    Fetch(Request),
    Done(Outcome),
}

impl Check {
    /// `handle` is the name libveritas verified the record set for
    /// (`Zone::handle`). Not the SIG record's handle field: libveritas checks
    /// the SIG's canonical name, but not its handle.
    pub fn new(claim: &Claim, handle: &str, ctx: &Context) -> Result<Check, HandleError> {
        let handle = Handle::parse(handle)?;
        let mut methods: Vec<Method> = claim
            .proofs
            .iter()
            .filter(|p| p.is_direct())
            .map(|p| match p {
                Proof::GitHubId(id) => Method::GitHub(*id),
                Proof::Tweet(id) => Method::Tweet(*id),
                Proof::BlueskyDid(did) => Method::Bluesky(did.clone()),
                Proof::Notary(_) => unreachable!("filtered out"),
            })
            .collect();
        // These platforms need no proof value: the claim says what to fetch.
        let implicit = match claim.platform {
            Platform::Mastodon => Some(Method::Mastodon),
            Platform::HackerNews => Some(Method::HackerNews),
            Platform::Website => Some(Method::Website),
            Platform::Nostr => Some(Method::Nostr),
            _ => None,
        };
        methods.extend(implicit);
        methods.extend(claim.proofs.iter().filter_map(|p| match p {
            Proof::Notary(n) => Some(Method::Notary(n.clone())),
            _ => None,
        }));
        Ok(Check {
            handle,
            claim: claim.clone(),
            ctx: ctx.clone(),
            methods,
            current: 0,
            stage: Stage::Idle,
            results: vec![],
        })
    }

    pub fn start(&mut self) -> Step {
        self.advance()
    }

    /// Hand back the response to the last [`Step::Fetch`], or the error
    /// message if the request couldn't be made.
    pub fn on_response(&mut self, response: Result<Response, String>) -> Step {
        if self.stage == Stage::Idle {
            return self.advance();
        }
        let resp = match response {
            Ok(r) => r,
            Err(e) => return self.finish(Outcome::Unavailable(format!("network error: {e}"))),
        };
        if resp.body.len() > MAX_BODY {
            return self.finish(failed(Failure::BadResponse("response too large".into())));
        }
        let next = match (self.methods[self.current].clone(), self.stage) {
            (Method::GitHub(id), Stage::Waiting) => self.github_profile(id, &resp),
            (Method::GitHub(_), _) => Next::Done(self.github_links(&resp)),
            (Method::Tweet(_), _) => Next::Done(self.tweet(&resp)),
            (Method::Bluesky(did), _) => Next::Done(self.bluesky(&did, &resp)),
            (Method::Mastodon, _) => Next::Done(self.mastodon(&resp)),
            (Method::HackerNews, _) => Next::Done(self.hackernews(&resp)),
            (Method::Website, _) => Next::Done(self.website(&resp)),
            (Method::Nostr | Method::Notary(_), _) => Next::Done(Outcome::Unavailable(
                "got an HTTP response for a check that didn't ask for one".into(),
            )),
        };
        match next {
            Next::Fetch(r) => {
                self.stage = Stage::GitHubLinks;
                Step::Fetch(r)
            }
            Next::Done(o) => self.finish(o),
        }
    }

    /// Hand back the raw events from the last [`Step::Query`], from all
    /// relays together.
    pub fn on_events(&mut self, events: Vec<String>) -> Step {
        if self.stage == Stage::Idle || !matches!(self.methods[self.current], Method::Nostr) {
            return self.advance();
        }
        let o = self.nostr(&events);
        self.finish(o)
    }

    fn advance(&mut self) -> Step {
        loop {
            let Some(method) = self.methods.get(self.current).cloned() else {
                return Step::Done(self.final_outcome());
            };
            self.stage = Stage::Waiting;
            match method {
                Method::Notary(p) => {
                    let o = self.notary(&p);
                    if matches!(o, Outcome::Verified(_)) {
                        return Step::Done(o);
                    }
                    self.results.push(o);
                    self.current += 1;
                }
                Method::GitHub(_) => return Step::Fetch(self.github_request("")),
                Method::Tweet(id) => {
                    return Step::Fetch(get(format!(
                        "https://publish.x.com/oembed?url=https://x.com/i/status/{id}&omit_script=1&dnt=true"
                    )));
                }
                Method::Bluesky(did) => {
                    return Step::Fetch(get(format!(
                        "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={did}"
                    )));
                }
                Method::Mastodon => {
                    let (user, server) = self.claim.account.split_once('@').unwrap_or_default();
                    return Step::Fetch(get(format!(
                        "https://{server}/api/v1/accounts/lookup?acct={user}"
                    )));
                }
                Method::HackerNews => {
                    return Step::Fetch(get(format!(
                        "https://hacker-news.firebaseio.com/v0/user/{}.json",
                        self.claim.account
                    )));
                }
                Method::Website => {
                    return Step::Fetch(get(format!(
                        "{}/.well-known/spaces.txt",
                        self.claim.account
                    )));
                }
                Method::Nostr => match self.relay_query() {
                    Some(q) => return Step::Query(q),
                    None => {
                        self.results
                            .push(Outcome::Unavailable("no relays to ask".into()));
                        self.current += 1;
                    }
                },
            }
        }
    }

    fn finish(&mut self, outcome: Outcome) -> Step {
        if matches!(outcome, Outcome::Verified(_)) {
            self.current = self.methods.len();
            self.stage = Stage::Idle;
            return Step::Done(outcome);
        }
        self.results.push(outcome);
        self.current += 1;
        self.stage = Stage::Idle;
        self.advance()
    }

    /// No method verified: report the first definite failure, otherwise the
    /// first "couldn't tell".
    fn final_outcome(&self) -> Outcome {
        self.results
            .iter()
            .find(|o| matches!(o, Outcome::Failed(_)))
            .or_else(|| self.results.first())
            .cloned()
            .unwrap_or(failed(Failure::NoProof))
    }

    fn verified(&self, source: Source, account: String, account_id: Option<String>) -> Outcome {
        Outcome::Verified(Verified {
            platform: self.claim.platform,
            account,
            source,
            via: Via::Platform,
            account_id,
        })
    }

    fn profile(&self, text: &str, links: &[String]) -> bool {
        profile_mentions(text, links, &self.handle)
    }

    // ---------- GitHub ----------

    fn github_request(&self, suffix: &str) -> Request {
        let mut r = get(format!(
            "https://api.github.com/users/{}{suffix}",
            self.claim.account
        ));
        r.headers
            .push(header("accept", "application/vnd.github+json"));
        r.headers.push(header("x-github-api-version", "2022-11-28"));
        if let Some(t) = &self.ctx.github_token {
            r.headers
                .push(header("authorization", &format!("Bearer {t}")));
        }
        r
    }

    fn github_profile(&self, pinned: u64, resp: &Response) -> Next {
        #[derive(Deserialize)]
        struct User {
            id: u64,
            name: Option<String>,
            bio: Option<String>,
            blog: Option<String>,
        }
        let u: User = match parse_json(resp, &[403, 429]) {
            Ok(u) => u,
            Err(o) => return Next::Done(o),
        };
        if u.id != pinned {
            return Next::Done(failed(Failure::AccountMismatch {
                found: format!("account id {}", u.id),
            }));
        }
        let id = Some(u.id.to_string());
        let account = self.claim.account.clone();
        let source = if u.bio.as_deref().is_some_and(|b| self.profile(b, &[])) {
            Some(Source::Bio)
        } else if u
            .name
            .as_deref()
            .is_some_and(|n| text_mentions(n, &self.handle))
        {
            Some(Source::DisplayName)
        } else if u
            .blog
            .as_deref()
            .is_some_and(|b| text_mentions(b, &self.handle))
        {
            Some(Source::Website)
        } else {
            None
        };
        match source {
            Some(s) => Next::Done(self.verified(s, account, id)),
            // The other profile links take a second request.
            None => Next::Fetch(self.github_request("/social_accounts")),
        }
    }

    fn github_links(&self, resp: &Response) -> Outcome {
        #[derive(Deserialize)]
        struct Link {
            url: String,
        }
        let links: Vec<Link> = match parse_json(resp, &[403, 429]) {
            Ok(l) => l,
            Err(o) => return o,
        };
        if links.iter().any(|l| text_mentions(&l.url, &self.handle)) {
            let id = match &self.methods[self.current] {
                Method::GitHub(id) => Some(id.to_string()),
                _ => None,
            };
            self.verified(Source::Website, self.claim.account.clone(), id)
        } else {
            failed(Failure::HandleNotFound)
        }
    }

    // ---------- X ----------

    fn tweet(&self, resp: &Response) -> Outcome {
        #[derive(Deserialize)]
        struct OEmbed {
            author_name: String,
            author_url: String,
            html: String,
        }
        // 403: protected tweet. Treated like a missing one.
        if resp.status == 403 {
            return failed(Failure::NotFound);
        }
        let o: OEmbed = match parse_json(resp, &[429]) {
            Ok(o) => o,
            Err(o) => return o,
        };
        // Never trust the request URL: oEmbed goes by tweet ID.
        let author = o.author_url.trim_end_matches('/').rsplit('/').next();
        let author = author.and_then(|a| Platform::X.normalize_username(a));
        if author.as_deref() != Some(self.claim.account.as_str()) {
            return failed(Failure::AccountMismatch {
                found: author.unwrap_or_default(),
            });
        }
        let account = self.claim.account.clone();
        if text_mentions(&o.author_name, &self.handle) {
            return self.verified(Source::DisplayName, account, None);
        }
        let text = html::parse(html::first_paragraph(&o.html).unwrap_or_default()).text;
        if post_claims(&text, &self.handle) {
            self.verified(Source::Post, account, None)
        } else {
            failed(Failure::HandleNotFound)
        }
    }

    // ---------- Bluesky ----------

    fn bluesky(&self, pinned: &str, resp: &Response) -> Outcome {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Profile {
            did: String,
            handle: String,
            display_name: Option<String>,
            description: Option<String>,
        }
        // The AppView answers 400 "Profile not found" for unknown accounts.
        if resp.status == 400 {
            return failed(Failure::NotFound);
        }
        let p: Profile = match parse_json(resp, &[429]) {
            Ok(p) => p,
            Err(o) => return o,
        };
        if p.did != pinned {
            return failed(Failure::AccountMismatch { found: p.did });
        }
        let source = if p
            .description
            .as_deref()
            .is_some_and(|d| self.profile(d, &[]))
        {
            Source::Bio
        } else if p
            .display_name
            .as_deref()
            .is_some_and(|n| text_mentions(n, &self.handle))
        {
            Source::DisplayName
        } else {
            return failed(Failure::HandleNotFound);
        };
        self.verified(source, p.handle, Some(p.did))
    }

    // ---------- Mastodon ----------

    fn mastodon(&self, resp: &Response) -> Outcome {
        #[derive(Deserialize)]
        struct Field {
            value: String,
        }
        #[derive(Deserialize)]
        struct Account {
            id: String,
            username: String,
            display_name: String,
            note: String,
            #[serde(default)]
            fields: Vec<Field>,
        }
        let a: Account = match parse_json(resp, &[429]) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let user = self.claim.account.split('@').next().unwrap_or_default();
        if !a.username.eq_ignore_ascii_case(user) {
            return failed(Failure::AccountMismatch { found: a.username });
        }
        let note = html::parse(&a.note);
        let source = if self.profile(&note.text, &note.links) {
            Source::Bio
        } else if text_mentions(&a.display_name, &self.handle) {
            Source::DisplayName
        } else if a.fields.iter().any(|f| {
            let v = html::parse(&f.value);
            self.profile(&v.text, &v.links)
        }) {
            Source::Website
        } else {
            return failed(Failure::HandleNotFound);
        };
        self.verified(source, self.claim.account.clone(), Some(a.id))
    }

    // ---------- Hacker News ----------

    fn hackernews(&self, resp: &Response) -> Outcome {
        #[derive(Deserialize)]
        struct User {
            id: String,
            about: Option<String>,
        }
        // Unknown users come back as 200 `null`.
        if resp.status == 200 && resp.body.trim_ascii() == b"null" {
            return failed(Failure::NotFound);
        }
        let u: User = match parse_json(resp, &[429]) {
            Ok(u) => u,
            Err(o) => return o,
        };
        if u.id != self.claim.account {
            return failed(Failure::AccountMismatch { found: u.id });
        }
        let about = html::parse(u.about.as_deref().unwrap_or_default());
        if self.profile(&about.text, &about.links) {
            self.verified(Source::Bio, u.id, None)
        } else {
            failed(Failure::HandleNotFound)
        }
    }

    // ---------- Websites ----------

    fn website(&self, resp: &Response) -> Outcome {
        // The proof is the site's TLS certificate, so the file must come
        // from the claimed origin over HTTPS, even after redirects.
        if !crate::platform::same_https_origin(&resp.url, &self.claim.account) {
            return failed(Failure::BadResponse(format!(
                "redirected away from {}",
                self.claim.account
            )));
        }
        match resp.status {
            200 => {}
            404 | 410 => return failed(Failure::NotFound),
            s => return status_outcome(s),
        }
        if resp.body.len() > MAX_WELL_KNOWN {
            return failed(Failure::BadResponse("spaces.txt is too large".into()));
        }
        let text = String::from_utf8_lossy(&resp.body);
        let listed = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .any(|l| Handle::parse(l).is_ok_and(|h| h == self.handle));
        if listed {
            self.verified(Source::WellKnown, self.claim.account.clone(), None)
        } else {
            failed(Failure::HandleNotFound)
        }
    }

    // ---------- Nostr ----------

    fn relay_query(&self) -> Option<RelayQuery> {
        let pubkey = nostr::parse_pubkey(&self.claim.account)?;
        let mut relays: Vec<String> = Vec::new();
        for r in self.claim.relays.iter().chain(&self.ctx.nostr_relays) {
            let r = r.trim_end_matches('/').to_string();
            if r.starts_with("wss://") && !relays.contains(&r) {
                relays.push(r);
            }
        }
        (!relays.is_empty()).then(|| RelayQuery {
            relays,
            filter: nostr::profile_filter(&pubkey),
        })
    }

    fn nostr(&self, events: &[String]) -> Outcome {
        let Some(pubkey) = nostr::parse_pubkey(&self.claim.account) else {
            return failed(Failure::NoProof);
        };
        let want = nostr::hex(&pubkey);
        // Relays can't forge events, but one may serve an old profile, so
        // take the newest valid one across all relays.
        let newest = events
            .iter()
            .filter_map(|raw| nostr::verify_event(raw).ok())
            .filter(|e| e.kind == 0 && e.pubkey.eq_ignore_ascii_case(&want))
            .max_by_key(|e| e.created_at);
        let Some(profile) = newest else {
            return Outcome::Unavailable("no profile found on the relays".into());
        };
        let handle = serde_json::from_str::<serde_json::Value>(&profile.content)
            .ok()
            .and_then(|v| v.get("handle")?.as_str().map(String::from));
        if handle.is_some_and(|h| Handle::parse(&h).is_ok_and(|h| h == self.handle)) {
            self.verified(Source::HandleField, self.claim.account.clone(), None)
        } else {
            failed(Failure::HandleNotFound)
        }
    }

    // ---------- Notary ----------

    fn notary(&self, proof: &NotaryProof) -> Outcome {
        match proof.verify(
            self.claim.platform,
            self.handle.as_str(),
            &self.claim.account,
            &self.ctx.trusted_notaries,
        ) {
            Ok(v) => Outcome::Verified(Verified {
                platform: self.claim.platform,
                account: v.attestation.username,
                source: v.attestation.source,
                via: Via::Notary {
                    key: v.notary,
                    issued_at: v.attestation.issued_at,
                },
                account_id: Some(v.attestation.account_id.to_string()),
            }),
            Err(e) => failed(Failure::BadNotaryProof(e)),
        }
    }
}

fn failed(f: Failure) -> Outcome {
    Outcome::Failed(f)
}

fn get(url: String) -> Request {
    Request {
        url,
        headers: vec![],
    }
}

fn header(name: &str, value: &str) -> Header {
    Header {
        name: name.into(),
        value: value.into(),
    }
}

fn status_outcome(status: u16) -> Outcome {
    match status {
        404 | 410 => failed(Failure::NotFound),
        429 => Outcome::Unavailable("rate limited".into()),
        s => Outcome::Unavailable(format!("HTTP {s}")),
    }
}

/// Parse a 200 JSON body. `limited` are statuses that mean "rate limited"
/// on this platform.
fn parse_json<T: serde::de::DeserializeOwned>(
    resp: &Response,
    limited: &[u16],
) -> Result<T, Outcome> {
    if limited.contains(&resp.status) {
        return Err(Outcome::Unavailable("rate limited".into()));
    }
    if resp.status != 200 {
        return Err(status_outcome(resp.status));
    }
    serde_json::from_slice(&resp.body).map_err(|e| failed(Failure::BadResponse(e.to_string())))
}

#[cfg(test)]
mod tests;
