//! Notary proofs, for accounts a client can't check itself (Telegram,
//! Instagram, or any platform the web can't reach).
//!
//! A notary checks the platform and signs an [`Attestation`]: *at
//! `issued_at`, account `account_id` on `platform`, named `username`,
//! pointed at `handle`*. Only what the record set doesn't already say is
//! stored. The proof is appended to the claim record as a value:
//!
//! ```text
//! { "type": "txt", "key": "telegram", "value": ["buffrr", "notary:AQTO..."] }
//! ```
//!
//! The platform comes from the record key, the username from the record's
//! first value and the handle from the verified zone (`Zone::handle`). The verifier
//! rebuilds the signed message from them, so a proof moved to another
//! record, handle or username fails. The notary key isn't stored either: the
//! verifier tries each key it trusts.
//!
//! Stored bytes (base64url, no padding, after `notary:`):
//!
//! ```text
//! version u8 | source u8 | issued_at CompactSize | account_id CompactSize | signature [64]
//! ```
//!
//! Signed message, hashed with the BIP-340 tag [`SIGHASH_TAG`]:
//!
//! ```text
//! version u8 | platform u8 | source u8 | issued_at u64 BE | account_id u64 BE
//! | handle_len u8 | handle | username_len u8 | username
//! ```
//!
//! CompactSize is Bitcoin's, as in SIP-7: minimal encodings only. The
//! username is in [`Platform::normalize_username`] form.

use crate::handle::{Handle, HandleError};
use crate::platform::Platform;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::secp256k1::{self, Keypair, Message, Secp256k1, XOnlyPublicKey, schnorr};
use std::fmt;
use std::sync::OnceLock;

/// Current encoding version.
pub const VERSION: u8 = 1;

/// Value prefix that marks a notary proof in a claim record.
pub const PREFIX: &str = "notary:";

/// BIP-340 tag for the signature hash. A dedicated tag keeps notary
/// signatures from ever being valid as a Spaces signed message (which uses
/// the `\x17Spaces Signed Message:\n` prefix) or any other protocol message.
pub const SIGHASH_TAG: &[u8] = b"crossverify/notary/v1";

const SIG_LEN: usize = 64;

/// Where on the platform the handle was found. Notary proofs sign it;
/// direct checks report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Source {
    /// Profile bio text, or a link inside it.
    Bio = 1,
    /// The profile's display name.
    DisplayName = 2,
    /// The profile's website field or other profile links.
    Website = 3,
    /// A post by the account (an X verification tweet or pinned post).
    Post = 4,
    /// The account owner confirmed the link with the notary's bot (Telegram).
    BotConfirmation = 5,
    /// A website's `/.well-known/spaces.txt`.
    WellKnown = 6,
    /// A field that exists to name the handle (the `handle` field of a
    /// Nostr profile, NIP-SPACES).
    HandleField = 7,
}

impl Source {
    pub const ALL: [Source; 7] = [
        Source::Bio,
        Source::DisplayName,
        Source::Website,
        Source::Post,
        Source::BotConfirmation,
        Source::WellKnown,
        Source::HandleField,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Source::Bio => "bio",
            Source::DisplayName => "display_name",
            Source::Website => "website",
            Source::Post => "post",
            Source::BotConfirmation => "bot_confirmation",
            Source::WellKnown => "well_known",
            Source::HandleField => "handle_field",
        }
    }

    fn from_u8(b: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|s| *s as u8 == b)
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// The full statement a notary signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub platform: Platform,
    pub source: Source,
    /// Unix seconds when the notary checked the platform.
    pub issued_at: u64,
    pub handle: Handle,
    /// Canonical username ([`Platform::normalize_username`]).
    pub username: String,
    /// Stable numeric account ID. Renames don't change it.
    pub account_id: u64,
}

/// What is stored after `notary:` in the claim record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotaryProof {
    pub source: Source,
    pub issued_at: u64,
    pub account_id: u64,
    pub signature: [u8; SIG_LEN],
}

/// A proof that checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub attestation: Attestation,
    /// Which trusted notary signed it.
    pub notary: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MissingPrefix,
    InvalidBase64,
    Truncated,
    TrailingBytes,
    NonMinimalInteger,
    UnsupportedVersion(u8),
    UnknownSource(u8),
    InvalidHandle(HandleError),
    InvalidUsername,
    /// No trusted notary signed this proof for this platform, handle and
    /// username: tampered, moved to another record, or signed by an
    /// untrusted key.
    NotVerified,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingPrefix => write!(f, "value doesn't start with {PREFIX:?}"),
            Error::InvalidBase64 => write!(f, "proof is not base64url"),
            Error::Truncated => write!(f, "proof is truncated"),
            Error::TrailingBytes => write!(f, "unexpected bytes after proof"),
            Error::NonMinimalInteger => write!(f, "non-minimal integer encoding"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported proof version {v}"),
            Error::UnknownSource(s) => write!(f, "unknown source {s}"),
            Error::InvalidHandle(e) => write!(f, "invalid handle: {e}"),
            Error::InvalidUsername => write!(f, "invalid username for this platform"),
            Error::NotVerified => write!(
                f,
                "not signed by a trusted notary for this account and handle"
            ),
        }
    }
}

impl std::error::Error for Error {}

fn verify_ctx() -> &'static Secp256k1<secp256k1::VerifyOnly> {
    static CTX: OnceLock<Secp256k1<secp256k1::VerifyOnly>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::verification_only)
}

/// BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || msg).
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn put_compact(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0xFC => out.push(v as u8),
        0xFD..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(v as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn compact(&mut self) -> Result<u64, Error> {
        let (v, min) = match self.u8()? {
            b @ 0..=0xFC => return Ok(b as u64),
            0xFD => (
                u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64,
                0xFD,
            ),
            0xFE => (
                u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64,
                0x1_0000,
            ),
            0xFF => (
                u64::from_le_bytes(self.take(8)?.try_into().unwrap()),
                0x1_0000_0000,
            ),
        };
        if v < min {
            return Err(Error::NonMinimalInteger);
        }
        Ok(v)
    }
}

impl Attestation {
    /// The bytes that get hashed and signed.
    pub fn signed_message(&self) -> Vec<u8> {
        let handle = self.handle.as_str().as_bytes();
        let username = self.username.as_bytes();
        let mut out = Vec::with_capacity(21 + handle.len() + username.len());
        out.push(VERSION);
        out.push(self.platform as u8);
        out.push(self.source as u8);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.account_id.to_be_bytes());
        // Handles are at most a few labels of 62 bytes and usernames at most
        // 39, so both fit a u8 length; `sign` rejects anything longer.
        out.push(handle.len() as u8);
        out.extend_from_slice(handle);
        out.push(username.len() as u8);
        out.extend_from_slice(username);
        out
    }

    /// The 32-byte BIP-340 message that gets signed.
    pub fn sighash(&self) -> [u8; 32] {
        tagged_hash(SIGHASH_TAG, &self.signed_message())
    }

    /// Sign with the notary key. `aux_rand` should be 32 fresh random bytes
    /// (BIP-340 auxiliary randomness).
    pub fn sign<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        keypair: &Keypair,
        aux_rand: &[u8; 32],
    ) -> Result<NotaryProof, Error> {
        // Only canonical usernames, so the verifier can rebuild this exact
        // message from whatever form the record holds.
        if self.platform.normalize_username(&self.username).as_deref()
            != Some(self.username.as_str())
        {
            return Err(Error::InvalidUsername);
        }
        if self.handle.as_str().len() > u8::MAX as usize {
            return Err(Error::InvalidHandle(HandleError::LabelTooLong));
        }
        let msg = Message::from_digest(self.sighash());
        let sig = secp.sign_schnorr_with_aux_rand(&msg, keypair, aux_rand);
        Ok(NotaryProof {
            source: self.source,
            issued_at: self.issued_at,
            account_id: self.account_id,
            signature: sig.serialize(),
        })
    }
}

impl NotaryProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 9 + 9 + SIG_LEN);
        out.push(VERSION);
        out.push(self.source as u8);
        put_compact(&mut out, self.issued_at);
        put_compact(&mut out, self.account_id);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse without verifying. Call [`verify`](Self::verify) before
    /// trusting anything in it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { buf: bytes, pos: 0 };
        let version = r.u8()?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let s = r.u8()?;
        let source = Source::from_u8(s).ok_or(Error::UnknownSource(s))?;
        let issued_at = r.compact()?;
        let account_id = r.compact()?;
        let signature = r.take(SIG_LEN)?.try_into().expect("64 bytes");
        if r.pos != bytes.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(NotaryProof {
            source,
            issued_at,
            account_id,
            signature,
        })
    }

    /// The record value: `notary:<base64url>`.
    pub fn to_value(&self) -> String {
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    /// Parse a record value (`notary:<base64url>`) without verifying.
    pub fn from_value(value: &str) -> Result<Self, Error> {
        let b64 = value.strip_prefix(PREFIX).ok_or(Error::MissingPrefix)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| Error::InvalidBase64)?;
        Self::from_bytes(&bytes)
    }

    /// Check the proof for the claim it was found in: `platform` from the
    /// record key, `username` from the record's first value (any form
    /// [`Platform::normalize_username`] accepts), `handle` the name
    /// libveritas verified the record set for (`Zone::handle`, not the SIG
    /// record's unchecked handle field).
    pub fn verify(
        &self,
        platform: Platform,
        handle: &str,
        username: &str,
        trusted: &[[u8; 32]],
    ) -> Result<Verified, Error> {
        let handle = Handle::parse(handle).map_err(Error::InvalidHandle)?;
        let username = platform
            .normalize_username(username)
            .ok_or(Error::InvalidUsername)?;
        let attestation = Attestation {
            platform,
            source: self.source,
            issued_at: self.issued_at,
            handle,
            username,
            account_id: self.account_id,
        };
        let msg = Message::from_digest(attestation.sighash());
        let sig =
            schnorr::Signature::from_slice(&self.signature).map_err(|_| Error::NotVerified)?;
        let notary = trusted
            .iter()
            .find(|k| {
                XOnlyPublicKey::from_slice(&k[..])
                    .is_ok_and(|pk| verify_ctx().verify_schnorr(&sig, &msg, &pk).is_ok())
            })
            .ok_or(Error::NotVerified)?;
        Ok(Verified {
            attestation,
            notary: *notary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> (Secp256k1<secp256k1::All>, Keypair, [u8; 32]) {
        let secp = Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let pk = kp.x_only_public_key().0.serialize();
        (secp, kp, pk)
    }

    fn sample() -> Attestation {
        Attestation {
            platform: Platform::Telegram,
            source: Source::BotConfirmation,
            issued_at: 1_794_078_176,
            handle: Handle::parse("buffrr@bitcoin").unwrap(),
            username: "buffrr".into(),
            account_id: 1_122_981_952,
        }
    }

    fn proof(seed: u8) -> (NotaryProof, [u8; 32]) {
        let (secp, kp, pk) = keypair(seed);
        (sample().sign(&secp, &kp, &[7; 32]).unwrap(), pk)
    }

    #[test]
    fn roundtrip_and_verify() {
        let (p, pk) = proof(1);
        let value = p.to_value();
        assert!(value.starts_with("notary:"));
        // 1 + 1 + 5 + 5 + 64 bytes → 101 base64url chars + prefix.
        assert_eq!(p.to_bytes().len(), 76);
        let parsed = NotaryProof::from_value(&value).unwrap();
        assert_eq!(parsed, p);
        let v = parsed
            .verify(Platform::Telegram, "buffrr@bitcoin", "buffrr", &[pk])
            .unwrap();
        assert_eq!(v.notary, pk);
        assert_eq!(v.attestation, sample());
    }

    #[test]
    fn username_in_any_record_form() {
        let (p, pk) = proof(1);
        for claim in ["buffrr", "@Buffrr", "https://t.me/buffrr", "t.me/BUFFRR"] {
            p.verify(Platform::Telegram, "buffrr@bitcoin", claim, &[pk])
                .unwrap_or_else(|e| panic!("{claim}: {e}"));
        }
        p.verify(Platform::Telegram, "Buffrr@Bitcoin", "buffrr", &[pk])
            .unwrap();
    }

    #[test]
    fn bound_to_platform_handle_username_and_key() {
        let (p, pk) = proof(1);
        let (_, _, other) = keypair(2);
        let ok = |platform, handle, user, keys: &[[u8; 32]]| {
            p.verify(platform, handle, user, keys).is_ok()
        };
        assert!(ok(Platform::Telegram, "buffrr@bitcoin", "buffrr", &[pk]));
        assert!(!ok(Platform::X, "buffrr@bitcoin", "buffrr", &[pk]));
        assert!(!ok(Platform::Telegram, "alice@bitcoin", "buffrr", &[pk]));
        assert!(!ok(Platform::Telegram, "buffrr@bitcoin", "alice_tg", &[pk]));
        assert!(!ok(
            Platform::Telegram,
            "buffrr@bitcoin",
            "buffrr",
            &[other]
        ));
        assert!(ok(
            Platform::Telegram,
            "buffrr@bitcoin",
            "buffrr",
            &[other, pk]
        ));
        assert_eq!(
            p.verify(Platform::Telegram, "buffrr@bitcoin", "x", &[pk]),
            Err(Error::InvalidUsername)
        );
    }

    #[test]
    fn detects_tampering() {
        let (p, pk) = proof(1);
        for f in [
            |p: &mut NotaryProof| p.issued_at += 1,
            |p: &mut NotaryProof| p.account_id += 1,
            |p: &mut NotaryProof| p.source = Source::Bio,
            |p: &mut NotaryProof| p.signature[10] ^= 1,
        ] {
            let mut t = p.clone();
            f(&mut t);
            assert_eq!(
                t.verify(Platform::Telegram, "buffrr@bitcoin", "buffrr", &[pk]),
                Err(Error::NotVerified)
            );
        }
    }

    #[test]
    fn rejects_malformed() {
        let (p, _) = proof(1);
        let bytes = p.to_bytes();
        assert_eq!(
            NotaryProof::from_bytes(&bytes[..bytes.len() - 1]),
            Err(Error::Truncated)
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(NotaryProof::from_bytes(&extra), Err(Error::TrailingBytes));
        let mut v2 = bytes.clone();
        v2[0] = 2;
        assert_eq!(
            NotaryProof::from_bytes(&v2),
            Err(Error::UnsupportedVersion(2))
        );
        // issued_at 5 written as 0xFD 0x05 0x00 instead of 0x05.
        let mut nm = vec![VERSION, Source::Bio as u8, 0xFD, 5, 0, 1];
        nm.extend_from_slice(&[0; 64]);
        assert_eq!(NotaryProof::from_bytes(&nm), Err(Error::NonMinimalInteger));
        assert_eq!(
            NotaryProof::from_value("proof:AAAA"),
            Err(Error::MissingPrefix)
        );
        assert_eq!(
            NotaryProof::from_value("notary:!!"),
            Err(Error::InvalidBase64)
        );
    }

    #[test]
    fn compact_size_roundtrip() {
        for v in [
            0,
            0xFC,
            0xFD,
            0xFFFF,
            0x1_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let mut out = vec![];
            put_compact(&mut out, v);
            let mut r = Reader { buf: &out, pos: 0 };
            assert_eq!(r.compact().unwrap(), v);
            assert_eq!(r.pos, out.len());
        }
    }

    #[test]
    fn sign_requires_canonical_username() {
        let (secp, kp, _) = keypair(1);
        let mut a = sample();
        a.username = "Buffrr".into();
        assert_eq!(a.sign(&secp, &kp, &[0; 32]), Err(Error::InvalidUsername));
    }

    #[test]
    fn domain_separated_from_spaces_signed_messages() {
        let a = sample();
        let mut engine = sha256::Hash::engine();
        engine.input(b"\x17Spaces Signed Message:\n");
        engine.input(&a.signed_message());
        let spaces_hash = sha256::Hash::from_engine(engine).to_byte_array();
        assert_ne!(spaces_hash, a.sighash());
    }
}
