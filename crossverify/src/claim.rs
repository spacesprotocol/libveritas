//! A claim, as the client passes it in: a record key and its values, taken
//! from a record set libveritas has already verified. SIP-7 parsing stays in
//! libveritas; this only reads the values.
//!
//! ```text
//! key "github",   values ["buffrr", "id:41967894"]
//! key "x",        values ["_buffrr", "tweet:2100240557159112799"]
//! key "telegram", values ["buffrr", "notary:AQX…"]
//! key "nostr",    values ["npub1…", "wss://relay.example.com"]
//! ```
//!
//! The first value names the account. Later values of the form
//! `<method>:<data>` are proofs; Nostr relay hints are kept separately.
//! Unknown or malformed proof values are ignored, like unknown SIP-7
//! records.

use crate::Platform;
use crate::notary::NotaryProof;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub platform: Platform,
    /// Canonical account ([`Platform::normalize_username`]).
    pub account: String,
    pub proofs: Vec<Proof>,
    /// Relay hints (`wss://…` values) on a Nostr claim.
    pub relays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// `id:<numeric id>`: pins a GitHub account.
    GitHubId(u64),
    /// `tweet:<id>`: an X post by the account.
    Tweet(u64),
    /// `did:<did>`: pins a Bluesky account (`did:did:plc:…`).
    BlueskyDid(String),
    /// `notary:<base64url>`: a notary checked it and signed the result.
    /// Only on Telegram and Instagram claims.
    Notary(NotaryProof),
}

impl Proof {
    /// Whether a client can check this proof itself, without trusting a
    /// notary.
    pub fn is_direct(&self) -> bool {
        !matches!(self, Proof::Notary(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// The record key isn't a platform this crate knows.
    UnsupportedKey(String),
    MissingAccount,
    InvalidAccount(String),
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimError::UnsupportedKey(k) => write!(f, "{k:?} is not a supported platform"),
            ClaimError::MissingAccount => write!(f, "record has no account value"),
            ClaimError::InvalidAccount(a) => write!(f, "{a:?} is not a valid account"),
        }
    }
}

impl std::error::Error for ClaimError {}

impl Claim {
    /// Read a claim from a record key and its values.
    pub fn new<S: AsRef<str>>(key: &str, values: &[S]) -> Result<Claim, ClaimError> {
        let platform =
            Platform::parse(key).ok_or_else(|| ClaimError::UnsupportedKey(key.to_string()))?;
        let (first, rest) = values.split_first().ok_or(ClaimError::MissingAccount)?;
        let account = platform
            .normalize_username(first.as_ref())
            .ok_or_else(|| ClaimError::InvalidAccount(first.as_ref().to_string()))?;
        let mut proofs = Vec::new();
        let mut relays = Vec::new();
        for v in rest.iter().map(|v| v.as_ref().trim()) {
            if platform == Platform::Nostr && (v.starts_with("wss://") || v.starts_with("ws://")) {
                relays.push(v.to_string());
            } else if let Some(p) = Proof::parse(platform, v) {
                proofs.push(p);
            }
        }
        Ok(Claim {
            platform,
            account,
            proofs,
            relays,
        })
    }

    pub fn profile_url(&self) -> String {
        self.platform.profile_url(&self.account)
    }
}

impl Proof {
    /// Parse one proof value. `None` for unknown methods, malformed data,
    /// or a method that doesn't belong to this platform.
    fn parse(platform: Platform, v: &str) -> Option<Proof> {
        let (method, data) = v.split_once(':')?;
        match (method, platform) {
            ("id", Platform::GitHub) => data.parse().ok().map(Proof::GitHubId),
            ("tweet", Platform::X) => data.parse().ok().map(Proof::Tweet),
            ("did", Platform::Bluesky) if data.starts_with("did:") && data.len() <= 256 => {
                Some(Proof::BlueskyDid(data.to_string()))
            }
            // Never for self-checked platforms: see `Platform::is_self_checked`.
            ("notary", p) if !p.is_self_checked() => {
                NotaryProof::from_value(v).ok().map(Proof::Notary)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_values() {
        let c = Claim::new(
            "github",
            &["https://github.com/Buffrr", "id:41967894", "foo:bar"],
        )
        .unwrap();
        assert_eq!(c.platform, Platform::GitHub);
        assert_eq!(c.account, "buffrr");
        assert_eq!(c.proofs, vec![Proof::GitHubId(41967894)]);
        assert_eq!(c.profile_url(), "https://github.com/buffrr");

        let c = Claim::new("x", &["@_buffrr", "tweet:2100240557159112799"]).unwrap();
        assert_eq!(c.proofs, vec![Proof::Tweet(2100240557159112799)]);

        let c = Claim::new("bluesky", &["alice.bsky.social", "did:did:plc:abc"]).unwrap();
        assert_eq!(c.proofs, vec![Proof::BlueskyDid("did:plc:abc".into())]);
    }

    #[test]
    fn ignores_foreign_and_malformed_proofs() {
        // A tweet proof on a GitHub claim, a non-numeric id, a broken notary value.
        let c = Claim::new("github", &["buffrr", "tweet:1", "id:abc", "notary:!!"]).unwrap();
        assert!(c.proofs.is_empty());
    }

    #[test]
    fn notary_only_where_nothing_else_works() {
        // A well-formed notary value on a GitHub claim is ignored, so a
        // stale attestation can't stand in for the direct check.
        let value = "notary:AQVkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(NotaryProof::from_value(value).is_ok());
        let gh = Claim::new("github", &["buffrr", value]).unwrap();
        assert!(gh.proofs.is_empty());
        let tg = Claim::new("telegram", &["buffrr", value]).unwrap();
        assert_eq!(tg.proofs.len(), 1);
    }

    #[test]
    fn nostr_relay_hints() {
        let pk = crate::nostr::tests::pubkey_of(1);
        let c = Claim::new(
            "nostr",
            &[crate::nostr::npub(&pk).as_str(), "wss://relay.example.com"],
        )
        .unwrap();
        assert_eq!(c.relays, vec!["wss://relay.example.com"]);
        assert!(c.proofs.is_empty());
    }

    #[test]
    fn errors() {
        assert_eq!(
            Claim::new("myspace", &["tom"]),
            Err(ClaimError::UnsupportedKey("myspace".into()))
        );
        assert_eq!(
            Claim::new("gh", &["buffrr"]),
            Err(ClaimError::UnsupportedKey("gh".into()))
        );
        assert_eq!(
            Claim::new::<&str>("x", &[]),
            Err(ClaimError::MissingAccount)
        );
        assert!(matches!(
            Claim::new("x", &["not valid!"]),
            Err(ClaimError::InvalidAccount(_))
        ));
    }
}
