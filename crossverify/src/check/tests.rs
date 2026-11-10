//! Checks driven with recorded responses. The GitHub and X bodies are
//! trimmed copies of what the real APIs returned on 2026-11-07/09.

use super::*;
use crate::nostr::tests::{pubkey_of, signed_event};

fn ok(url: &str, body: &str) -> Result<Response, String> {
    status(200, url, body)
}

fn status(status: u16, url: &str, body: &str) -> Result<Response, String> {
    Ok(Response {
        status,
        url: url.into(),
        body: body.as_bytes().to_vec(),
    })
}

/// Drive a check with canned responses, asserting the URLs it asks for.
fn run(
    key: &str,
    values: &[&str],
    handle: &str,
    mut replies: Vec<(&str, Result<Response, String>)>,
) -> Outcome {
    run_with(
        key,
        values,
        handle,
        &Context::default(),
        &mut replies,
        vec![],
    )
}

fn run_with(
    key: &str,
    values: &[&str],
    handle: &str,
    ctx: &Context,
    replies: &mut Vec<(&str, Result<Response, String>)>,
    events: Vec<String>,
) -> Outcome {
    let claim = Claim::new(key, values).unwrap();
    let mut check = Check::new(&claim, handle, ctx).unwrap();
    let mut step = check.start();
    replies.reverse();
    let mut events = Some(events);
    loop {
        step = match step {
            Step::Fetch(req) => {
                let (want, reply) = replies.pop().expect("unexpected request");
                assert_eq!(req.url, want);
                check.on_response(reply)
            }
            Step::Query(q) => {
                assert!(q.filter.contains("\"kinds\":[0]"));
                check.on_events(events.take().expect("unexpected relay query"))
            }
            Step::Done(o) => {
                assert!(replies.is_empty(), "requests not made: {replies:?}");
                return o;
            }
        }
    }
}

fn verified(o: &Outcome) -> &Verified {
    match o {
        Outcome::Verified(v) => v,
        other => panic!("expected verified, got {other}"),
    }
}

// ---------- GitHub ----------

const GH_USER: &str = "https://api.github.com/users/buffrr";
const GH_LINKS: &str = "https://api.github.com/users/buffrr/social_accounts";
const BUFFRR: &str = r#"{"login":"buffrr","id":41967894,"type":"User","name":"Buffrr",
  "bio":"PGP: 5E18 8EC1 571D 32AC F1B8 85CC 12B0 037C E1D4 54E5\r\n\r\n","blog":"https://buffrr.dev"}"#;
const BUFFRR_LINKS: &str = r#"[{"provider":"twitter","url":"https://twitter.com/_buffrr"},
  {"provider":"generic","url":"https://nacho.io/buffrr@bitcoin"}]"#;

#[test]
fn github_profile_link() {
    let o = run(
        "github",
        &["buffrr", "id:41967894"],
        "buffrr@bitcoin",
        vec![
            (GH_USER, ok(GH_USER, BUFFRR)),
            (GH_LINKS, ok(GH_LINKS, BUFFRR_LINKS)),
        ],
    );
    let v = verified(&o);
    assert_eq!(v.source, Source::Website);
    assert_eq!(v.via, Via::Platform);
    assert_eq!(v.account_id.as_deref(), Some("41967894"));
}

#[test]
fn github_bio_needs_one_request() {
    let body = BUFFRR.replace("PGP:", "Engineer at buffrr@bitcoin. PGP:");
    let o = run(
        "github",
        &["buffrr", "id:41967894"],
        "buffrr@bitcoin",
        vec![(GH_USER, ok(GH_USER, &body))],
    );
    assert_eq!(verified(&o).source, Source::Bio);
}

#[test]
fn github_username_taken_over() {
    let o = run(
        "github",
        &["buffrr", "id:1"],
        "buffrr@bitcoin",
        vec![(GH_USER, ok(GH_USER, BUFFRR))],
    );
    assert!(
        matches!(o, Outcome::Failed(Failure::AccountMismatch { .. })),
        "{o}"
    );
}

#[test]
fn github_not_pointing_back_and_errors() {
    let o = run(
        "github",
        &["buffrr", "id:41967894"],
        "alice@bitcoin",
        vec![
            (GH_USER, ok(GH_USER, BUFFRR)),
            (GH_LINKS, ok(GH_LINKS, BUFFRR_LINKS)),
        ],
    );
    assert_eq!(o, Outcome::Failed(Failure::HandleNotFound));

    let o = run(
        "github",
        &["buffrr", "id:41967894"],
        "buffrr@bitcoin",
        vec![(GH_USER, status(403, GH_USER, "{}"))],
    );
    assert!(matches!(o, Outcome::Unavailable(_)), "{o}");

    let o = run(
        "github",
        &["buffrr", "id:41967894"],
        "buffrr@bitcoin",
        vec![(GH_USER, Err("timeout".into()))],
    );
    assert!(matches!(o, Outcome::Unavailable(_)), "{o}");
}

#[test]
fn github_token_header() {
    let claim = Claim::new("github", &["buffrr", "id:41967894"]).unwrap();
    let ctx = Context {
        github_token: Some("t".into()),
        ..Context::default()
    };
    let mut check = Check::new(&claim, "buffrr@bitcoin", &ctx).unwrap();
    let Step::Fetch(req) = check.start() else {
        panic!("expected a fetch")
    };
    assert!(
        req.headers
            .iter()
            .any(|h| h.name == "authorization" && h.value == "Bearer t")
    );
}

// ---------- X ----------

const TWEET: &str = "https://publish.x.com/oembed?url=https://x.com/i/status/2100240557159112799&omit_script=1&dnt=true";

fn oembed(author_name: &str, author: &str, text: &str) -> String {
    serde_json::json!({
        "url": "https://x.com/_buffrr/status/2100240557159112799",
        "author_name": author_name,
        "author_url": format!("https://x.com/{author}"),
        "html": format!(
            "<blockquote class=\"twitter-tweet\"><p lang=\"en\" dir=\"ltr\">{text}</p>&mdash; {author_name} (@{author}) <a href=\"https://x.com/{author}/status/2100240557159112799\">September 16, 2026</a></blockquote>\n"
        ),
        "provider_name": "X",
    })
    .to_string()
}

#[test]
fn x_display_name() {
    // The real response for _buffrr's tweet: display name buffrr@bitcoin.
    let body = oembed(
        "buffrr@bitcoin",
        "_buffrr",
        "Get your@bitcoin handle through the Nacho app! <a href=\"https://t.co/hradbWSklT\">https://t.co/hradbWSklT</a>",
    );
    let o = run(
        "x",
        &["_buffrr", "tweet:2100240557159112799"],
        "buffrr@bitcoin",
        vec![(TWEET, ok(TWEET, &body))],
    );
    assert_eq!(verified(&o).source, Source::DisplayName);
}

#[test]
fn x_verification_tweet() {
    let body = oembed(
        "Buffrr",
        "_buffrr",
        "Verifying myself: I am buffrr@bitcoin <a href=\"https://t.co/x\">nacho.io/buffrr@bitcoin</a>",
    );
    let o = run(
        "x",
        &["_buffrr", "tweet:2100240557159112799"],
        "buffrr@bitcoin",
        vec![(TWEET, ok(TWEET, &body))],
    );
    assert_eq!(verified(&o).source, Source::Post);
}

#[test]
fn x_mentions_and_other_authors_fail() {
    let insult = oembed("Bob", "_buffrr", "buffrr@bitcoin is an idiot");
    let o = run(
        "x",
        &["_buffrr", "tweet:2100240557159112799"],
        "buffrr@bitcoin",
        vec![(TWEET, ok(TWEET, &insult))],
    );
    assert_eq!(o, Outcome::Failed(Failure::HandleNotFound));

    // Someone else's tweet, even one that verifies their own handle.
    let other = oembed("Bob", "bob", "Verifying myself: I am buffrr@bitcoin");
    let o = run(
        "x",
        &["_buffrr", "tweet:2100240557159112799"],
        "buffrr@bitcoin",
        vec![(TWEET, ok(TWEET, &other))],
    );
    assert_eq!(
        o,
        Outcome::Failed(Failure::AccountMismatch {
            found: "bob".into()
        })
    );

    let o = run(
        "x",
        &["_buffrr", "tweet:2100240557159112799"],
        "buffrr@bitcoin",
        vec![(TWEET, status(404, TWEET, ""))],
    );
    assert_eq!(o, Outcome::Failed(Failure::NotFound));
}

#[test]
fn x_without_tweet_has_no_proof() {
    let o = run("x", &["_buffrr"], "buffrr@bitcoin", vec![]);
    assert_eq!(o, Outcome::Failed(Failure::NoProof));
}

// ---------- Bluesky ----------

const BSKY: &str = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=did:plc:z72i7hdynmk6r22z27h6tvur";

#[test]
fn bluesky() {
    let body = r#"{"did":"did:plc:z72i7hdynmk6r22z27h6tvur","handle":"alice.com",
      "displayName":"Alice","description":"Spaces: nacho.io/alice@bitcoin"}"#;
    let o = run(
        "bluesky",
        &["alice.bsky.social", "did:did:plc:z72i7hdynmk6r22z27h6tvur"],
        "alice@bitcoin",
        vec![(BSKY, ok(BSKY, body))],
    );
    let v = verified(&o);
    assert_eq!(v.source, Source::Bio);
    // Looked up by DID, so a handle change is fine; report the current one.
    assert_eq!(v.account, "alice.com");

    let o = run(
        "bluesky",
        &["alice.bsky.social", "did:did:plc:z72i7hdynmk6r22z27h6tvur"],
        "alice@bitcoin",
        vec![(
            BSKY,
            status(
                400,
                BSKY,
                r#"{"error":"InvalidRequest","message":"Profile not found"}"#,
            ),
        )],
    );
    assert_eq!(o, Outcome::Failed(Failure::NotFound));
}

// ---------- Mastodon ----------

const MASTO: &str = "https://mastodon.social/api/v1/accounts/lookup?acct=alice";

#[test]
fn mastodon_profile_field() {
    let body = r#"{"id":"109","username":"alice","acct":"alice","display_name":"Alice",
      "note":"<p>Builder</p>","fields":[{"name":"Spaces","value":"<a href=\"https://nacho.io/alice@bitcoin\" rel=\"me\">nacho.io/alice@bitcoin</a>"}]}"#;
    let o = run(
        "mastodon",
        &["@alice@mastodon.social"],
        "alice@bitcoin",
        vec![(MASTO, ok(MASTO, body))],
    );
    let v = verified(&o);
    assert_eq!(v.source, Source::Website);
    assert_eq!(v.account_id.as_deref(), Some("109"));
}

// ---------- Hacker News ----------

const HN: &str = "https://hacker-news.firebaseio.com/v0/user/pg.json";

#[test]
fn hacker_news() {
    let body = r#"{"id":"pg","about":"Bug fixer. I am pg&#x40;bitcoin","created":1160418092}"#;
    let o = run(
        "hackernews",
        &["pg"],
        "pg@bitcoin",
        vec![(HN, ok(HN, body))],
    );
    assert_eq!(verified(&o).source, Source::Bio);

    // The real answer for pg: no handle in "Bug fixer."
    let real = r#"{"about":"Bug fixer.","created":1160418092,"id":"pg","karma":157316}"#;
    let o = run(
        "hackernews",
        &["pg"],
        "pg@bitcoin",
        vec![(HN, ok(HN, real))],
    );
    assert_eq!(o, Outcome::Failed(Failure::HandleNotFound));

    let o = run(
        "hackernews",
        &["pg"],
        "pg@bitcoin",
        vec![(HN, ok(HN, "null"))],
    );
    assert_eq!(o, Outcome::Failed(Failure::NotFound));
}

// ---------- Websites ----------

const SITE: &str = "https://buffrr.dev/.well-known/spaces.txt";

#[test]
fn website() {
    let body = "# Spaces handles for this site\nbuffrr@bitcoin\nteam.buffrr@bitcoin\n";
    let o = run(
        "website",
        &["buffrr.dev"],
        "buffrr@bitcoin",
        vec![(SITE, ok(SITE, body))],
    );
    assert_eq!(verified(&o).source, Source::WellKnown);

    let o = run(
        "website",
        &["buffrr.dev"],
        "alice@bitcoin",
        vec![(SITE, ok(SITE, body))],
    );
    assert_eq!(o, Outcome::Failed(Failure::HandleNotFound));

    let o = run(
        "website",
        &["buffrr.dev"],
        "buffrr@bitcoin",
        vec![(SITE, status(404, SITE, ""))],
    );
    assert_eq!(o, Outcome::Failed(Failure::NotFound));
}

#[test]
fn website_rejects_redirects_away() {
    for final_url in [
        "https://evil.example/.well-known/spaces.txt",
        "http://buffrr.dev/.well-known/spaces.txt",
    ] {
        let o = run(
            "website",
            &["buffrr.dev"],
            "buffrr@bitcoin",
            vec![(SITE, ok(final_url, "buffrr@bitcoin\n"))],
        );
        assert!(
            matches!(o, Outcome::Failed(Failure::BadResponse(_))),
            "{final_url}: {o}"
        );
    }
}

// ---------- Nostr ----------

#[test]
fn nostr_newest_profile_wins() {
    let npub = crate::nostr::npub(&pubkey_of(5));
    let old = signed_event(5, 100, 0, r#"{"name":"alice","handle":"alice@bitcoin"}"#);
    let new = signed_event(5, 200, 0, r#"{"name":"alice"}"#);
    let mut none = vec![];

    // A forged "newer" profile (content changed, so its id no longer
    // matches) is ignored; the valid one with the handle counts.
    let forged = new.replace(r#"\"name\":\"alice\""#, r#"\"name\":\"mallory\""#);
    assert_ne!(forged, new);
    let o = run_with(
        "nostr",
        &[&npub, "wss://relay.example.com"],
        "alice@bitcoin",
        &Context::default(),
        &mut none,
        vec![forged, old.clone()],
    );
    assert_eq!(verified(&o).source, Source::HandleField);

    // Newest removed the handle → failed, even though a relay still has the old one.
    let o = run_with(
        "nostr",
        &[&npub],
        "alice@bitcoin",
        &Context::default(),
        &mut none,
        vec![old, new],
    );
    assert_eq!(o, Outcome::Failed(Failure::HandleNotFound));
}

#[test]
fn nostr_ignores_other_keys_and_reports_empty() {
    let npub = crate::nostr::npub(&pubkey_of(5));
    let someone_else = signed_event(6, 300, 0, r#"{"handle":"alice@bitcoin"}"#);
    let mut none = vec![];
    let o = run_with(
        "nostr",
        &[&npub],
        "alice@bitcoin",
        &Context::default(),
        &mut none,
        vec![someone_else],
    );
    assert!(matches!(o, Outcome::Unavailable(_)), "{o}");
}

#[test]
fn nostr_relays_from_claim_and_context() {
    let npub = crate::nostr::npub(&pubkey_of(5));
    let claim = Claim::new(
        "nostr",
        &[npub.as_str(), "wss://hint.example/", "wss://purplepag.es"],
    )
    .unwrap();
    let mut check = Check::new(&claim, "alice@bitcoin", &Context::default()).unwrap();
    let Step::Query(q) = check.start() else {
        panic!("expected a relay query")
    };
    assert_eq!(
        q.relays,
        vec![
            "wss://hint.example",
            "wss://purplepag.es",
            "wss://relay.damus.io"
        ]
    );
}

// ---------- Notary ----------

fn notary_value(seed: u8, platform: Platform, username: &str, handle: &str) -> (String, [u8; 32]) {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap());
    let a = notary::Attestation {
        platform,
        source: Source::BotConfirmation,
        issued_at: 1_794_078_176,
        handle: Handle::parse(handle).unwrap(),
        username: username.into(),
        account_id: 1_122_981_952,
    };
    let proof = a.sign(&secp, &kp, &[0; 32]).unwrap();
    (proof.to_value(), kp.x_only_public_key().0.serialize())
}

#[test]
fn notary_offline() {
    let (value, key) = notary_value(3, Platform::Telegram, "buffrr", "buffrr@bitcoin");
    let ctx = Context {
        trusted_notaries: vec![key],
        ..Context::default()
    };
    let o = run_with(
        "telegram",
        &["@buffrr", &value],
        "buffrr@bitcoin",
        &ctx,
        &mut vec![],
        vec![],
    );
    let v = verified(&o);
    assert_eq!(
        v.via,
        Via::Notary {
            key,
            issued_at: 1_794_078_176
        }
    );
    assert_eq!(v.account_id.as_deref(), Some("1122981952"));

    // Untrusted key, or no trusted keys at all.
    let o = run_with(
        "telegram",
        &["buffrr", &value],
        "buffrr@bitcoin",
        &Context::default(),
        &mut vec![],
        vec![],
    );
    assert!(
        matches!(o, Outcome::Failed(Failure::BadNotaryProof(_))),
        "{o}"
    );
}

#[test]
fn no_downgrade_to_notary_on_self_checked_platforms() {
    // A valid, trusted notary attestation for a GitHub account must never
    // stand in for the direct check.
    let (value, key) = notary_value(3, Platform::GitHub, "buffrr", "buffrr@bitcoin");
    let ctx = Context {
        trusted_notaries: vec![key],
        ..Context::default()
    };

    // Blocked or rate-limited request: stays unavailable, no fallback.
    let o = run_with(
        "github",
        &["buffrr", &value, "id:41967894"],
        "buffrr@bitcoin",
        &ctx,
        &mut vec![(GH_USER, status(403, GH_USER, ""))],
        vec![],
    );
    assert!(matches!(o, Outcome::Unavailable(_)), "{o}");

    // Revoked (handle gone from the profile): fails, the old snapshot doesn't count.
    let o = run_with(
        "github",
        &["buffrr", &value, "id:41967894"],
        "alice@bitcoin",
        &ctx,
        &mut vec![
            (GH_USER, ok(GH_USER, BUFFRR)),
            (GH_LINKS, ok(GH_LINKS, BUFFRR_LINKS)),
        ],
        vec![],
    );
    assert_eq!(o, Outcome::Failed(Failure::HandleNotFound));

    // Notary proof alone: nothing to check.
    let o = run_with(
        "github",
        &["buffrr", &value],
        "buffrr@bitcoin",
        &ctx,
        &mut vec![],
        vec![],
    );
    assert_eq!(o, Outcome::Failed(Failure::NoProof));
}
