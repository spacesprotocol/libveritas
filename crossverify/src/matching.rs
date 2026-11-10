//! Decide whether profile text or a post points at a handle.
//!
//! Matching is a plain text scan: a handle counts wherever it appears with
//! word boundaries, including inside a link (`nacho.io/alice@bitcoin`,
//! `example.com/x/alice@bitcoin`). Links aren't parsed. Profile fields are
//! written by the account owner, and a badge also needs the handle's signed
//! records to claim the account, so the only thing to guard against is a
//! handle-like string appearing innocently. Hence the boundaries:
//! `alice@bitcoin.com`, `xalice@bitcoin` and `pay.alice@bitcoin` don't match
//! `alice@bitcoin`.
//!
//! What counts depends on who wrote the text:
//! - Profile fields ([`profile_mentions`]): the handle anywhere counts. Only
//!   the owner writes their profile, so the badge means "this account
//!   publicly links to this handle".
//! - Posts ([`post_claims`]): must start with [`POST_PREFIX`] and the handle.
//!   Posts mention other people all the time ("alice@bitcoin is an idiot").

use crate::Handle;

fn is_label_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// Whether `text` contains the handle with word boundaries. `%40` counts as
/// `@`, for links that percent-encode it.
pub fn text_mentions(text: &str, handle: &Handle) -> bool {
    let hay = text.to_lowercase().replace("%40", "@");
    let needle = handle.as_str();
    hay.match_indices(needle).any(|(i, _)| {
        let before = hay[..i].chars().next_back();
        let bad_before = matches!(before, Some(c) if is_label_char(c) || c == '.' || c == '_');
        !bad_before && ends_at_boundary(&hay[i + needle.len()..])
    })
}

/// Whether the text after a handle ends it: `alice@bitcoin.com`,
/// `alice@bitcoins` and `alice@bitcoin@x` continue it; `alice@bitcoin.`
/// ends a sentence.
fn ends_at_boundary(after: &str) -> bool {
    let mut it = after.chars();
    match (it.next(), it.next()) {
        (Some(c), _) if is_label_char(c) || c == '_' || c == '@' => false,
        (Some('.'), Some(c)) => !c.is_alphanumeric(),
        _ => true,
    }
}

/// The sentence a post must start with to claim a handle.
pub const POST_PREFIX: &str = "Verifying myself: I am ";

/// Whether a post claims `handle`: it starts with
/// `Verifying myself: I am <handle>` (case-insensitive, leading whitespace
/// ignored), the handle ending at a word boundary. Anything may follow, such
/// as a link.
pub fn post_claims(text: &str, handle: &Handle) -> bool {
    let t = text.trim_start().to_lowercase();
    let want = format!("{}{}", POST_PREFIX.to_lowercase(), handle.as_str());
    t.strip_prefix(&want).is_some_and(ends_at_boundary)
}

/// Whether a profile field points at `handle`: in its text or in one of its
/// link targets.
pub fn profile_mentions(text: &str, links: &[String], handle: &Handle) -> bool {
    text_mentions(text, handle) || links.iter().any(|l| text_mentions(l, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Handle {
        Handle::parse(s).unwrap()
    }

    #[test]
    fn text_matches_with_boundaries() {
        let alice = h("alice@bitcoin");
        for t in [
            "alice@bitcoin",
            "⚡ alice@bitcoin · builder",
            "ALICE@BITCOIN",
            "find me: alice@bitcoin.",
            "(alice@bitcoin)",
            "@alice@bitcoin",
            "x alice@bitcoin\nnext line",
        ] {
            assert!(text_mentions(t, &alice), "{t:?} should match");
        }
    }

    #[test]
    fn text_rejects_lookalikes() {
        let alice = h("alice@bitcoin");
        for t in [
            "alice@bitcoin.com",
            "xalice@bitcoin",
            "pay.alice@bitcoin",
            "alice@bitcoins",
            "alice@bitcoin-dev",
            "alice@bitcoin@other",
            "alice_x@bitcoin",
            "alice @bitcoin",
            "",
        ] {
            assert!(!text_mentions(t, &alice), "{t:?} should not match");
        }
    }

    #[test]
    fn links() {
        let alice = h("alice@bitcoin");
        for t in [
            "https://nacho.io/alice@bitcoin",
            "nacho.io/alice@bitcoin",
            "https://www.nacho.io/Alice%40Bitcoin",
            "https://example.com/u/alice@bitcoin/",
            "site: nacho.io/alice@bitcoin.",
            // Odd, but written by the profile's owner.
            "mailto:alice@bitcoin",
            "https://nacho.io/?h=alice@bitcoin",
        ] {
            assert!(text_mentions(t, &alice), "{t:?} should match");
        }
        for t in [
            "https://nacho.io/alice@bitcoin.com",
            "https://alice@bitcoin.com/",
            "https://nacho.io/xalice@bitcoin",
            "https://nacho.io/pay.alice@bitcoin",
        ] {
            assert!(!text_mentions(t, &alice), "{t:?} should not match");
        }
    }

    #[test]
    fn posts_need_the_sentence() {
        let alice = h("alice@bitcoin");
        for t in [
            "Verifying myself: I am alice@bitcoin",
            "Verifying myself: I am alice@bitcoin nacho.io/alice@bitcoin",
            "  verifying myself: i am Alice@Bitcoin.",
            "Verifying myself: I am alice@bitcoin https://t.co/x",
        ] {
            assert!(post_claims(t, &alice), "{t:?} should claim");
        }
        for t in [
            "alice@bitcoin is an idiot",
            "big fan of alice@bitcoin",
            "@bob Verifying myself: I am alice@bitcoin",
            "lol \"Verifying myself: I am alice@bitcoin\"",
            "Verifying myself: I am nacho.io/alice@bitcoin",
            "Verifying myself: I am alice@bitcoin.com",
            "Verifying myself: I am alice@bitcoins",
        ] {
            assert!(!post_claims(t, &alice), "{t:?} should not claim");
        }
    }

    #[test]
    fn profile_fields() {
        let alice = h("alice@bitcoin");
        assert!(profile_mentions("Engineer at alice@bitcoin", &[], &alice));
        assert!(profile_mentions(
            "site",
            &["https://nacho.io/alice@bitcoin".into()],
            &alice
        ));
        assert!(!profile_mentions("alice@bitcoin.com", &[], &alice));
    }
}
