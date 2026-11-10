# libveritas_crossverify

Checks that an account on another platform points back at a Spaces handle.

A handle's signed SIP-7 record set claims an account (`github: ["buffrr", …]`).
That's one direction. This crate checks the other direction: that the
account says it belongs to the handle. Both together are a verified link.

**Trustless where possible.** Most platforms are checked directly. A notary
  is used only where nothing else works like Telegram.

## Claims and proofs

A claim is a record's key and values. The first value names the account;
later `<method>:<data>` values are proofs.

| Key | Example values | Checked against | Request |
|---|---|---|---|
| `github` | `["buffrr", "id:41967894"]` | bio, name, website, profile links; ID pinned | `api.github.com/users/{u}` (+ `/social_accounts` if needed) |
| `x` | `["_buffrr", "tweet:2100240557159112799"]` | display name, or a tweet starting `Verifying myself: I am <handle>` | `publish.x.com/oembed` |
| `bluesky` | `["alice.bsky.social", "did:did:plc:…"]` | bio, display name; DID pinned | `public.api.bsky.app/…/getProfile` |
| `mastodon` | `["@alice@mastodon.social"]` | bio, display name, profile fields | `{server}/api/v1/accounts/lookup` |
| `hackernews` | `["pg"]` | `about` field | `hacker-news.firebaseio.com/v0/user/{u}.json` |
| `website` | `["https://example.com"]` | `/.well-known/spaces.txt` lists the handle | over HTTPS only; trust is the site's TLS |
| `nostr` | `["npub1…", "wss://relay…"]` | newest valid `kind:0` has `"handle"` ([NIP-SPACES]) | relay query |
| `telegram` | `["buffrr", "notary:AQX…"]` | notary attestation, offline | none |
| `instagram` | `["alice", "notary:AQX…"]` | notary attestation, offline | none |

Unknown or malformed proof values are ignored, like unknown SIP-7
records.

**Profile fields vs. posts.** In a profile field (bio, display name, website,
links) a bare `alice@bitcoin` or `nacho.io/alice@bitcoin` counts: only the
owner writes their profile, so the badge means "this account links to this
handle". A post must *start with* `Verifying myself: I am alice@bitcoin`.

**Notaries only where nothing else works.** Notary proofs are accepted for
Telegram and Instagram only (`Platform::is_self_checked`). On every other
platform they're ignored.

## Use

```rust
use libveritas_crossverify::{Check, Claim, Context, Step};

let claim = Claim::new("github", &["buffrr", "id:41967894"])?;
let mut check = Check::new(&claim, "buffrr@bitcoin", &Context::default())?;

let mut step = check.start();
let outcome = loop {
    step = match step {
        Step::Fetch(req) => check.on_response(http_get(&req)),  // Ok(Response) or Err(message)
        Step::Query(q) => check.on_events(query_relays(&q)),   // raw EVENT payloads
        Step::Done(outcome) => break outcome,                  // Verified | Failed | Unavailable
    };
};
```

Run one loop per claim and update each badge when its loop finishes.
`Context` holds the trusted notary keys, default Nostr relays
and an optional GitHub token (servers only, never in an app).

With the `fetch` feature (reqwest + WebSockets), `fetch::Verifier` runs the
checks itself, concurrently, yielding results as they arrive:

```rust
let verifier = libveritas_crossverify::fetch::Verifier::new(Context::default());
let mut results = verifier.verify_each("buffrr@bitcoin", &claims)?;
while let Some(Checked { index, outcome }) = results.next().await {
    println!("{}: {outcome}", claims[index].platform);
}
```

```sh
cargo run -p libveritas_crossverify --features fetch --example verify -- \
    buffrr@bitcoin github=buffrr,id:41967894 x=_buffrr,tweet:2100240557159112799
```

## Notary proofs

`notary:` + base64url of `version | source | issued_at | account_id | signature`
(about 76 bytes). The platform, handle and username aren't stored; the verifier
rebuilds the signed message from the claim, so a proof copied to another
record, handle or username fails. BIP-340 Schnorr over a tagged hash
(`crossverify/notary/v1`). The verifier tries each trusted key.

