//! Nostr keys and events, for NIP-SPACES checks.
//!
//! The claim is the SIP-7 ADDR record `nostr: ["npub1…", "wss://…"]`; the
//! reverse link is the `handle` field in the key's latest `kind:0` profile
//! event (NIP-SPACES). This module decodes npubs and verifies events
//! (NIP-01 id + BIP-340 signature). A Nostr client doing its own half of
//! NIP-SPACES can use [`verify_event`] directly.

use bitcoin::bech32::{self, Bech32, Hrp};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr};
use serde::Deserialize;
use serde_json::Value;

const NPUB: Hrp = Hrp::parse_unchecked("npub");

/// 32-byte x-only public key from an `npub1…` string or 64 hex characters.
pub fn parse_pubkey(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    let bytes = if s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()) {
        hex_decode(s)?
    } else {
        let (hrp, data) = bech32::decode(s).ok()?;
        if hrp != NPUB {
            return None;
        }
        data
    };
    let key: [u8; 32] = bytes.try_into().ok()?;
    XOnlyPublicKey::from_slice(&key).ok()?;
    Some(key)
}

pub fn npub(pubkey: &[u8; 32]) -> String {
    bech32::encode_lower::<Bech32>(NPUB, pubkey).expect("32 bytes always encode")
}

pub(crate) fn normalize_npub(s: &str) -> Option<String> {
    parse_pubkey(s).map(|k| npub(&k))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// A Nostr event as relays send it.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Value,
    pub content: String,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    Malformed,
    WrongId,
    BadSignature,
}

/// Parse a raw event and check its NIP-01 id and BIP-340 signature.
pub fn verify_event(raw: &str) -> Result<Event, EventError> {
    let ev: Event = serde_json::from_str(raw).map_err(|_| EventError::Malformed)?;
    let pubkey: [u8; 32] = hex_decode(&ev.pubkey)
        .and_then(|b| b.try_into().ok())
        .ok_or(EventError::Malformed)?;
    // NIP-01: sha256 of the compact JSON array [0, pubkey, created_at, kind, tags, content].
    let serialized = serde_json::to_string(&serde_json::json!([
        0,
        ev.pubkey,
        ev.created_at,
        ev.kind,
        ev.tags,
        ev.content
    ]))
    .map_err(|_| EventError::Malformed)?;
    let id = sha256::Hash::hash(serialized.as_bytes()).to_byte_array();
    if hex(&id) != ev.id.to_ascii_lowercase() {
        return Err(EventError::WrongId);
    }
    let sig = hex_decode(&ev.sig)
        .and_then(|b| schnorr::Signature::from_slice(&b).ok())
        .ok_or(EventError::Malformed)?;
    let pk = XOnlyPublicKey::from_slice(&pubkey).map_err(|_| EventError::Malformed)?;
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(id), &pk)
        .map_err(|_| EventError::BadSignature)?;
    Ok(ev)
}

/// The relay filter for a key's latest profile (`kind:0`).
pub(crate) fn profile_filter(pubkey: &[u8; 32]) -> String {
    serde_json::json!({ "kinds": [0], "authors": [hex(pubkey)], "limit": 1 }).to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, SecretKey};

    /// Build a signed event the way a Nostr client would.
    pub(crate) fn signed_event(seed: u8, created_at: u64, kind: u64, content: &str) -> String {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap());
        let pubkey = hex(&kp.x_only_public_key().0.serialize());
        let serialized = serde_json::to_string(&serde_json::json!([
            0,
            pubkey,
            created_at,
            kind,
            [],
            content
        ]))
        .unwrap();
        let id = sha256::Hash::hash(serialized.as_bytes()).to_byte_array();
        let sig = secp.sign_schnorr_with_aux_rand(&Message::from_digest(id), &kp, &[1; 32]);
        serde_json::json!({
            "id": hex(&id), "pubkey": pubkey, "created_at": created_at, "kind": kind,
            "tags": [], "content": content, "sig": hex(&sig.serialize()),
        })
        .to_string()
    }

    pub(crate) fn pubkey_of(seed: u8) -> [u8; 32] {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
            .x_only_public_key()
            .0
            .serialize()
    }

    #[test]
    fn npub_roundtrip() {
        let pk = pubkey_of(1);
        let n = npub(&pk);
        assert!(n.starts_with("npub1"));
        assert_eq!(parse_pubkey(&n), Some(pk));
        assert_eq!(parse_pubkey(&n.to_uppercase()), Some(pk));
        assert_eq!(parse_pubkey(&hex(&pk)), Some(pk));
        assert_eq!(normalize_npub(&hex(&pk)), Some(n));
        assert_eq!(parse_pubkey("npub1notvalid"), None);
    }

    #[test]
    fn verifies_events() {
        let raw = signed_event(1, 1_700_000_000, 0, r#"{"handle":"alice@bitcoin"}"#);
        let ev = verify_event(&raw).unwrap();
        assert_eq!(ev.kind, 0);
        // Tampered content: the id no longer matches.
        let tampered = raw.replace("alice@bitcoin", "mallory@bitcoin");
        assert_eq!(verify_event(&tampered).unwrap_err(), EventError::WrongId);
        assert_eq!(verify_event("{}").unwrap_err(), EventError::Malformed);
    }

    #[test]
    fn nip01_escaping_matches() {
        // Content with characters NIP-01 escapes; the id is computed over
        // serde_json's compact output on both sides.
        let raw = signed_event(2, 1, 0, "line\nquote\" back\\slash tab\t ✓");
        verify_event(&raw).unwrap();
    }
}
