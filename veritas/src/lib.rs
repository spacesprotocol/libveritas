use crate::cert::{Certificate, Witness, Signature};
use crate::sname::{NameLike, SName};
use borsh::{BorshDeserialize, BorshSerialize};
use libveritas_zk::guest::CommitmentKind;
use risc0_zkvm::{Receipt, VerifierContext};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spaces_protocol::Bytes;
use spaces_protocol::bitcoin::hashes::{Hash as HashUtil, sha256, HashEngine};
use spaces_protocol::bitcoin::secp256k1::{self, XOnlyPublicKey};
use spaces_protocol::bitcoin::{ScriptBuf};
use spaces_protocol::constants::{ChainAnchor, SPACES_SIGNED_MSG_PREFIX};
use spaces_protocol::slabel::SLabel;
use spaces_ptr::constants::COMMITMENT_FINALITY_INTERVAL;
use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Write};
use spacedb::subtree::SubTree;
use spaces_ptr::RootAnchor;
use crate::msg::OffchainData;

pub mod cert;
pub mod msg;
pub mod sname;

/// Result of verifying a message.
///
/// Contains the verified zones and the original message data.
/// The message can be used to construct certificates for storage.
pub struct VerifiedMessage {
    pub zones: Vec<Zone>,
    pub message: msg::Message,
}

impl VerifiedMessage {
    /// Create a certificate for a verified handle.
    ///
    /// Returns `None` if the handle was not verified in this message.
    pub fn certificate(&self, handle: &SName) -> Option<Certificate> {
        if !self.zones.iter().any(|z| &z.handle == handle) {
            return None;
        }

        let space = handle.space()?;
        let bundle = self.message.spaces.iter().find(|b| b.space == space)?;

        if handle.is_single_label() {
            return Some(Certificate::new(
                handle.clone(),
                Witness::Root {
                    receipt: bundle.receipt.clone(),
                    cert_relay: bundle.cert_relay.clone(),
                },
            ));
        }

        let label = handle.subspace()?;

        for epoch in &bundle.epochs {
            let Some(h) = epoch.handles.iter().find(|h| h.name == label) else {
                continue;
            };
            return Some(Certificate::new(
                handle.clone(),
                Witness::Leaf {
                    genesis_spk: h.genesis_spk.clone(),
                    handles: epoch.tree.clone(),
                    signature: h.signature,
                },
            ));
        }
        None
    }

    /// Iterate over all certificates from this verified message.
    pub fn certificates(&self) -> CertificateIter<'_> {
        CertificateIter {
            zones: &self.zones,
            bundles: self.message.spaces.iter(),
            // Context for building certs (handle iterator doesn't carry parent refs)
            current_bundle: None,
            current_epoch: None,
            epochs: None,
            handles: None,
        }
    }
}

/// Iterator over certificates from a verified message.
pub struct CertificateIter<'a> {
    zones: &'a [Zone],
    bundles: std::slice::Iter<'a, msg::Bundle>,
    current_bundle: Option<&'a msg::Bundle>,
    current_epoch: Option<&'a msg::Epoch>,
    epochs: Option<std::slice::Iter<'a, msg::Epoch>>,
    handles: Option<std::slice::Iter<'a, msg::Handle>>,
}

impl<'a> Iterator for CertificateIter<'a> {
    type Item = Certificate;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Try to emit a handle from current epoch
            if let Some(handles) = &mut self.handles {
                if let Some(h) = handles.next() {
                    let bundle = self.current_bundle?;
                    let epoch = self.current_epoch?;
                    let subject = SName::join(&h.name, &bundle.space).ok()?;

                    return Some(Certificate::new(
                        subject,
                        Witness::Leaf {
                            genesis_spk: h.genesis_spk.clone(),
                            handles: epoch.tree.clone(),
                            signature: h.signature,
                        },
                    ));
                }
            }

            // Try next epoch
            if let Some(epochs) = &mut self.epochs {
                if let Some(epoch) = epochs.next() {
                    self.current_epoch = Some(epoch);
                    self.handles = Some(epoch.handles.iter());
                    continue;
                }
            }

            // Try next bundle
            let bundle = self.bundles.next()?;
            self.current_bundle = Some(bundle);
            self.epochs = Some(bundle.epochs.iter());
            self.current_epoch = None;
            self.handles = None;

            // Emit root cert if zone exists
            let root_handle = SName::from_space(&bundle.space).ok()?;
            if self.zones.iter().any(|z| z.handle == root_handle) {
                return Some(Certificate::new(
                    root_handle,
                    Witness::Root {
                        receipt: bundle.receipt.clone(),
                        cert_relay: bundle.cert_relay.clone(),
                    },
                ));
            }
        }
    }
}

#[derive(Clone)]
pub struct Veritas {
    tip: RootAnchor,
    anchors: Vec<RootAnchor>,
    /// The oldest anchor (block height) we have a root anchor for
    oldest_anchor: u32,
    /// The newest anchor (block height) we have a root anchor for
    newest_anchor: u32,
    /// When true, uses dev-mode verification for ZK receipts (accepts FakeReceipts).
    dev_mode: bool,
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SovereigntyState {
    /// Fully sovereign — independent and self-governing.
    Sovereign,

    /// Pending — commitment not yet finalized.
    /// May eventually become sovereign or remain dependent.
    Pending,

    /// Dependent — under external authority, not self-governing.
    Dependent,
}

impl fmt::Display for SovereigntyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sovereign => write!(f, "sovereign"),
            Self::Pending => write!(f, "pending"),
            Self::Dependent => write!(f, "dependent"),
        }
    }
}

/// A verified zone representing ownership and state for a space handle.
///
/// Zones are produced by verifying certificates against on-chain anchors.
/// They contain all proven information about a handle's current state,
/// including ownership, delegation, and commitment data.
#[derive(Clone, Serialize, Deserialize)]
pub struct Zone {
    /// The block height of the anchor used to prove this zone (snapshot version).
    pub anchor: u32,
    /// The sovereignty state indicating finality of the zone's commitment.
    pub sovereignty: SovereigntyState,
    /// The space handle this zone represents (e.g., "alice@bitcoin").
    pub handle: SName,
    /// The current script pubkey that controls this handle.
    pub script_pubkey: ScriptBuf,
    /// Optional on-chain data associated with the handle.
    pub data: Option<Bytes>,
    /// Optional off-chain data signed by the handle owner
    pub offchain_data: Option<OffchainData>,
    /// Delegate information if the handle has delegated signing authority.
    pub delegate: ProvableOption<Delegate>,
    /// Commitment information including state root and finality status.
    pub commitment: ProvableOption<CommitmentInfo>,
}


/// Information about a space's commitment state.
#[derive(Clone, Serialize, Deserialize)]
pub struct CommitmentInfo {
    /// The on-chain commitment data.
    pub onchain: spaces_ptr::Commitment,
    /// Hash of the ZK receipt that proved this commitment (if verified).
    #[serde(
        serialize_with = "serialize_option_hash",
        deserialize_with = "deserialize_option_hash"
    )]
    pub receipt_hash: Option<Hash>,
}

impl CommitmentInfo {
    pub fn empty() -> Self {
        let empty_root = SubTree::<Sha256Hasher>::empty()
            .compute_root().expect("valid");
        Self {
            onchain: spaces_ptr::Commitment {
                state_root: empty_root,
                prev_root: None,
                rolling_hash: empty_root,
                block_height: 0,
            },
            receipt_hash: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Delegate {
    pub script_pubkey: ScriptBuf,
    pub data: Option<Bytes>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProvableOption<T> {
    Exists { value: T },
    Empty,
    Unknown,
}

impl BorshSerialize for SovereigntyState {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let variant: u8 = match self {
            Self::Sovereign => 0,
            Self::Pending => 1,
            Self::Dependent => 2,
        };
        BorshSerialize::serialize(&variant, writer)
    }
}

impl BorshDeserialize for SovereigntyState {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let variant = u8::deserialize_reader(reader)?;
        match variant {
            0 => Ok(Self::Sovereign),
            1 => Ok(Self::Pending),
            2 => Ok(Self::Dependent),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid SovereigntyState variant: {}", variant),
            )),
        }
    }
}

impl BorshSerialize for Delegate {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.script_pubkey.as_bytes().to_vec(), writer)?;
        BorshSerialize::serialize(&self.data.clone().map(|b| b.to_vec()), writer)
    }
}

impl BorshDeserialize for Delegate {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let spk_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        let data: Option<Vec<u8>> = Option::deserialize_reader(reader)?;
        Ok(Delegate {
            script_pubkey: ScriptBuf::from_bytes(spk_bytes),
            data: data.map(Bytes::new),
        })
    }
}

impl BorshSerialize for CommitmentInfo {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.onchain, writer)?;
        BorshSerialize::serialize(&self.receipt_hash, writer)
    }
}

impl BorshDeserialize for CommitmentInfo {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let onchain = spaces_ptr::Commitment::deserialize_reader(reader)?;
        let receipt_hash = Option::<Hash>::deserialize_reader(reader)?;
        Ok(CommitmentInfo { onchain, receipt_hash })
    }
}

impl<T: BorshSerialize> BorshSerialize for ProvableOption<T> {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            Self::Exists { value } => {
                BorshSerialize::serialize(&0u8, writer)?;
                BorshSerialize::serialize(value, writer)
            }
            Self::Empty => BorshSerialize::serialize(&1u8, writer),
            Self::Unknown => BorshSerialize::serialize(&2u8, writer),
        }
    }
}

impl<T: BorshDeserialize> BorshDeserialize for ProvableOption<T> {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let variant = u8::deserialize_reader(reader)?;
        match variant {
            0 => {
                let value = T::deserialize_reader(reader)?;
                Ok(Self::Exists { value })
            }
            1 => Ok(Self::Empty),
            2 => Ok(Self::Unknown),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid ProvableOption variant: {}", variant),
            )),
        }
    }
}

impl BorshSerialize for Zone {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.anchor, writer)?;
        BorshSerialize::serialize(&self.sovereignty, writer)?;
        BorshSerialize::serialize(&self.handle, writer)?;
        BorshSerialize::serialize(&self.script_pubkey.as_bytes().to_vec(), writer)?;
        BorshSerialize::serialize(&self.data.clone().map(|b| b.to_vec()), writer)?;
        BorshSerialize::serialize(&self.offchain_data, writer)?;
        BorshSerialize::serialize(&self.delegate, writer)?;
        BorshSerialize::serialize(&self.commitment, writer)
    }
}

impl BorshDeserialize for Zone {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let anchor = u32::deserialize_reader(reader)?;
        let sovereignty = SovereigntyState::deserialize_reader(reader)?;
        let handle = SName::deserialize_reader(reader)?;
        let spk_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        let data: Option<Vec<u8>> = Option::deserialize_reader(reader)?;
        let offchain_data = Option::<OffchainData>::deserialize_reader(reader)?;
        let delegate: ProvableOption<Delegate> = ProvableOption::deserialize_reader(reader)?;
        let commitment: ProvableOption<CommitmentInfo> = ProvableOption::deserialize_reader(reader)?;

        Ok(Zone {
            anchor,
            sovereignty,
            handle,
            script_pubkey: ScriptBuf::from_bytes(spk_bytes),
            data: data.map(Bytes::new),
            offchain_data,
            delegate,
            commitment,
        })
    }
}

pub fn hash_signable_message(msg: &[u8]) -> secp256k1::Message {
    let mut engine = sha256::Hash::engine();
    engine.input(SPACES_SIGNED_MSG_PREFIX);
    engine.input(msg);
    let digest = sha256::Hash::from_engine(engine);
    secp256k1::Message::from_digest(digest.to_byte_array())
}

/// Verify a Schnorr signature over a message using the Spaces signed-message prefix.
///
/// - `msg`: the raw message bytes (will be prefixed and hashed internally)
/// - `signature`: 64-byte Schnorr signature
/// - `pubkey`: 32-byte x-only public key
pub fn verify_spaces_message(msg: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> Result<(), SignatureError> {
    let xonly = XOnlyPublicKey::from_slice(pubkey)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    let sig = secp256k1::schnorr::Signature::from_slice(signature)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let hashed = hash_signable_message(msg);
    secp256k1::Secp256k1::verification_only()
        .verify_schnorr(&sig, &hashed, &xonly)
        .map_err(|_| SignatureError::VerificationFailed)
}

/// Verify a raw Schnorr signature (no prefix, caller provides the 32-byte message hash).
///
/// - `msg_hash`: 32-byte SHA256 hash of the message
/// - `signature`: 64-byte Schnorr signature
/// - `pubkey`: 32-byte x-only public key
pub fn verify_schnorr(msg_hash: &[u8; 32], signature: &[u8; 64], pubkey: &[u8; 32]) -> Result<(), SignatureError> {
    let xonly = XOnlyPublicKey::from_slice(pubkey)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    let sig = secp256k1::schnorr::Signature::from_slice(signature)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let msg = secp256k1::Message::from_digest(*msg_hash);
    secp256k1::Secp256k1::verification_only()
        .verify_schnorr(&sig, &msg, &xonly)
        .map_err(|_| SignatureError::VerificationFailed)
}

impl Zone {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("zone serialization should not fail")
    }

    /// Returns the zone serialized for signing.
    ///
    /// The `anchor` and `offchain_data` fields are zeroed out so delegate
    /// signatures remain valid across different anchor snapshots and
    /// don't include owner-signed data.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut zone = self.clone();
        zone.anchor = 0;
        zone.offchain_data = None;
        borsh::to_vec(&zone).expect("zone serialization should not fail")
    }

    /// Verify the offchain_data signature against the zone's script_pubkey.
    fn verify_offchain_data(&self) -> Result<(), SignatureError> {
        let offchain = self.offchain_data.as_ref()
            .ok_or(SignatureError::InvalidSignature)?;

        let script_bytes = self.script_pubkey.as_bytes();
        if script_bytes.len() != secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE + 2 {
            return Err(SignatureError::InvalidPublicKey);
        }
        let pubkey = XOnlyPublicKey::from_slice(&script_bytes[2..])
            .map_err(|_| SignatureError::InvalidPublicKey)?;

        let msg = hash_signable_message(&offchain.signing_bytes());
        let sig = secp256k1::schnorr::Signature::from_slice(&offchain.signature.0)
            .map_err(|_| SignatureError::InvalidSignature)?;

        secp256k1::Secp256k1::verification_only()
            .verify_schnorr(&sig, &msg, &pubkey)
            .map_err(|_| SignatureError::VerificationFailed)
    }

    /// Verify a schnorr signature over this zone.
    ///
    /// The message is the borsh-serialized zone data (with anchor zeroed),
    /// prefixed with the spaces signed message prefix and hashed with SHA256.
    pub fn verify_signature(&self, signature: &Signature, signer: &ScriptBuf) -> Result<(), SignatureError> {
        let script_bytes = signer.as_bytes();
        if script_bytes.len() != secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE + 2 {
            return Err(SignatureError::InvalidPublicKey);
        }
        let pubkey = XOnlyPublicKey::from_slice(&script_bytes[2..])
            .map_err(|_| SignatureError::InvalidPublicKey)?;

        let msg = hash_signable_message(&self.signing_bytes());
        let sig = secp256k1::schnorr::Signature::from_slice(&signature.0)
            .map_err(|_| SignatureError::InvalidSignature)?;

        secp256k1::Secp256k1::verification_only()
            .verify_schnorr(&sig, &msg, &pubkey)
            .map_err(|_| SignatureError::VerificationFailed)
    }


    /// Returns true if self is fresher/better than other.
    ///
    /// Comparison order:
    /// 1. Higher commitment height (receipts are expensive, keep the latest)
    /// 2. Commitment knowledge (Exists > Empty > Unknown)
    /// 3. Delegate knowledge (Exists > Empty > Unknown)
    /// 4. Higher offchain_data seq (owner-signed data freshness)
    /// 5. Higher anchor (fresher chain state, tiebreaker only)
    ///
    /// Anchor is checked last to prevent attackers from downgrading cached
    /// state by sending messages with higher anchors but incomplete proofs.
    ///
    /// Returns an error if the zones are for different handles.
    pub fn is_better_than(&self, other: &Self) -> Result<bool, ZoneCompareError> {
        if self.handle != other.handle {
            return Err(ZoneCompareError::DifferentHandles);
        }

        // Higher commitment height = newer committed state
        match (&self.commitment, &other.commitment) {
            (ProvableOption::Exists { value: a }, ProvableOption::Exists { value: b }) => {
                if a.onchain.block_height != b.onchain.block_height {
                    return Ok(a.onchain.block_height > b.onchain.block_height);
                }
            }
            (ProvableOption::Exists { .. }, _) => return Ok(true),
            (_, ProvableOption::Exists { .. }) => return Ok(false),
            (ProvableOption::Empty, ProvableOption::Unknown) => return Ok(true),
            (ProvableOption::Unknown, ProvableOption::Empty) => return Ok(false),
            _ => {}
        }

        // Delegate knowledge
        match (&self.delegate, &other.delegate) {
            (ProvableOption::Exists { .. }, ProvableOption::Empty | ProvableOption::Unknown) => return Ok(true),
            (ProvableOption::Empty | ProvableOption::Unknown, ProvableOption::Exists { .. }) => return Ok(false),
            (ProvableOption::Empty, ProvableOption::Unknown) => return Ok(true),
            (ProvableOption::Unknown, ProvableOption::Empty) => return Ok(false),
            _ => {}
        }

        // Higher offchain_data seq = newer owner-signed data
        // If seq is equal, compare data hashes for deterministic ordering
        match (&self.offchain_data, &other.offchain_data) {
            (Some(a), Some(b)) => if a.is_better_than(b) {
                return Ok(true);
            }
            (Some(_), None) => return Ok(true),
            (None, Some(_)) => return Ok(false),
            _ => {}
        }

        // Higher anchor = fresher chain state (tiebreaker)
        if self.anchor != other.anchor {
            return Ok(self.anchor > other.anchor);
        }

        Ok(false) // equal
    }

    /// Copy receipt_hash from other if commitment roots match.
    /// Avoids re-verifying ZK receipts for commitments we've already verified.
    pub fn update_receipt_cache(&mut self, other: &Self) {
        if let (
            ProvableOption::Exists { value: mine },
            ProvableOption::Exists { value: theirs },
        ) = (&mut self.commitment, &other.commitment) {
            if mine.onchain.state_root == theirs.onchain.state_root && mine.receipt_hash.is_none() {
                mine.receipt_hash = theirs.receipt_hash;
            }
        }
    }
    
    /// Returns true if the zone has a commitment that requires ZK verification.
    ///
    /// Returns false if:
    /// - Already ZK-verified (has receipt_hash)
    /// - First commitment (prev_root is None, nothing to prove transition from)
    /// - No commitment exists
    /// - Commitment is unknown
    pub fn requires_receipt(&mut self) -> Option<&mut CommitmentInfo> {
        match &mut self.commitment {
            ProvableOption::Exists { value } => {
                if value.receipt_hash.is_some() {
                    return None;
                }
                if value.onchain.prev_root.is_none() {
                    return None;
                }
                Some(value)
            }
            _ => None,
        }
    }
}

fn verify_receipt(ci: &mut CommitmentInfo, space: &SLabel, receipt: &Receipt, dev_mode: bool) -> Result<(), MessageError> {
    let space_str = space.to_string();
    let zkc = decode_journal(receipt, space)?;
    verify_zk_journal_matches_onchain(space, &zkc, &ci.onchain)?;
    let ctx = VerifierContext::default().with_dev_mode(dev_mode);
    let image_id = match zkc.kind {
        CommitmentKind::Fold => libveritas_methods::FOLD_ID,
        CommitmentKind::Step => libveritas_methods::STEP_ID,
    };
    receipt
        .verify_with_context(&ctx, image_id)
        .map_err(|e| MessageError::ReceiptInvalid {
            space: space_str,
            reason: e.to_string(),
        })?;
    let receipt_hash = hash_receipt(receipt);
    ci.receipt_hash = Some(receipt_hash);
    Ok(())
}

#[derive(Debug, Clone)]
pub enum SignatureError {
    /// Script pubkey is not a valid schnorr public key
    InvalidPublicKey,
    /// Signature bytes are malformed
    InvalidSignature,
    /// Signature verification failed
    VerificationFailed,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid schnorr public key"),
            Self::InvalidSignature => write!(f, "invalid signature format"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for SignatureError {}

#[derive(Debug, Clone)]
pub enum ZoneCompareError {
    /// Cannot compare zones for different handles
    DifferentHandles,
}

impl fmt::Display for ZoneCompareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DifferentHandles => write!(f, "cannot compare zones for different handles"),
        }
    }
}

impl std::error::Error for ZoneCompareError {}

/// Error when loading or updating anchors.
#[derive(Debug, Clone)]
pub enum AnchorError {
    /// Anchors must be sorted by height in descending order
    NotSorted,
    /// At least one anchor is required
    Empty,
}

impl fmt::Display for AnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSorted => write!(f, "anchors must be sorted by height in descending order"),
            Self::Empty => write!(f, "at least one anchor is required"),
        }
    }
}

impl std::error::Error for AnchorError {}

impl Veritas {
    pub fn from_anchors(anchors: Vec<RootAnchor>) -> Result<Self, AnchorError> {
        if anchors.is_empty() {
            return Err(AnchorError::Empty);
        }
        // Anchors must be sorted by height in descending order (newest first)
        if !anchors.iter().rev().is_sorted_by_key(|a| a.block.height) {
            return Err(AnchorError::NotSorted);
        }
        let newest_anchor = anchors[0].block.height;
        let oldest_anchor = anchors.last().unwrap().block.height;
        Ok(Veritas {
            tip: anchors[0].clone(),
            anchors,
            oldest_anchor,
            newest_anchor,
            dev_mode: false,
        })
    }

    pub fn oldest_anchor(&self) -> u32 {
        self.oldest_anchor
    }

    pub fn newest_anchor(&self) -> u32 {
        self.newest_anchor
    }

    pub fn update(&mut self, anchors: Vec<RootAnchor>) -> Result<(), AnchorError> {
        if anchors.is_empty() {
            return Err(AnchorError::Empty);
        }
        if !anchors.iter().rev().is_sorted_by_key(|a| a.block.height) {
            return Err(AnchorError::NotSorted);
        }
        self.tip = anchors[0].clone();
        self.newest_anchor = anchors[0].block.height;
        self.oldest_anchor = anchors.last().unwrap().block.height;
        self.anchors = anchors;
        Ok(())
    }

    pub fn set_dev_mode(&mut self, enabled: bool) {
        self.dev_mode = enabled;
    }

    /// Check if a commitment at the given block height is finalized.
    pub fn is_finalized(&self, commitment_height: u32) -> bool {
        let time_passed = self.tip.block.height.saturating_sub(commitment_height);
        time_passed >= COMMITMENT_FINALITY_INTERVAL
    }

    /// Get sovereignty state for a commitment at the given block height.
    pub fn sovereignty_for(&self, commitment_height: u32) -> SovereigntyState {
        if self.is_finalized(commitment_height) {
            SovereigntyState::Sovereign
        } else {
            SovereigntyState::Pending
        }
    }

    /// Verify a message and return verified zones along with sanitized message data.
    ///
    /// Uses `ctx.zones` for parent lookups and `is_better_than` comparison.
    /// If `ctx.requests` is empty, verifies all handles in the message.
    /// Otherwise, only verifies requested handles.
    ///
    /// Returns `VerifiedMessage` containing the best zone for each handle
    /// and sanitized message data (only verified bundles/epochs/handles/receipts).
    pub fn verify_message(&self, ctx: &msg::QueryContext, msg: crate::msg::Message) -> Result<VerifiedMessage, MessageError> {
        let anchor = self.check_msg_anchor(&msg)?;
        self.check_msg_chain_proofs(&msg, &anchor)?;
        self.check_msg_duplicate_spaces(&msg)?;

        let mut zones = Vec::new();
        let mut verified_bundles = Vec::new();

        for bundle in msg.spaces {
            let (bundle_zones, verified_bundle) =
                self.verify_bundle(ctx, &msg.anchor, &msg.chain, bundle)?;
            zones.extend(bundle_zones);
            if let Some(vb) = verified_bundle {
                verified_bundles.push(vb);
            }
        }

        Ok(VerifiedMessage {
            zones,
            message: msg::Message {
                anchor: msg.anchor,
                chain: msg.chain,
                spaces: verified_bundles,
            },
        })
    }


    fn verify_bundle(
        &self,
        ctx: &msg::QueryContext,
        anchor: &ChainAnchor,
        chain: &msg::ChainProof,
        bundle: msg::Bundle,
    ) -> Result<(Vec<Zone>, Option<msg::Bundle>), MessageError> {
        let space = bundle.space.clone();
        let cached_parent = ctx.get_parent_zone(&space);
        let mut extracted = self.extract_parent_zone(anchor, chain, &bundle)?;

        let root_handle = SName::from_space(&space)
            .map_err(|_| MessageError::InvalidSubject { subject: space.to_string() })?;

        let mut zones: Vec<Zone> = Vec::new();
        let mut receipt_verified = false;

        // Resolve which parent zone to use
        let target_zone: &Zone = match (&cached_parent, &mut extracted) {
            (Some(cached), Some(zone)) => {
                zone.update_receipt_cache(cached);
                if zone.is_better_than(cached).unwrap_or(false) {
                    receipt_verified = maybe_verify_receipt(zone, bundle.receipt.as_ref(), &space, self.dev_mode)?;
                    zone
                } else {
                    *cached
                }
            }
            (Some(cached), None) => *cached,
            (None, Some(zone)) => {
                receipt_verified = maybe_verify_receipt(zone, bundle.receipt.as_ref(), &space, self.dev_mode)?;
                zone
            }
            (None, None) => {
                return Err(MessageError::ParentZoneRequired { space: space.to_string() });
            }
        };

        let wants_root = ctx.wants(&root_handle);
        if wants_root {
            zones.push(target_zone.clone());
        }

        let verified_tip = match target_zone.commitment.clone() {
            ProvableOption::Exists { value } => value,
            ProvableOption::Empty => CommitmentInfo::empty(),
            ProvableOption::Unknown => {
                // Nothing left to verify - return bundle only if root was wanted
                let verified_bundle = if wants_root {
                    Some(msg::Bundle {
                        space,
                        receipt: if receipt_verified { bundle.receipt } else { None },
                        epochs: vec![],
                        cert_relay: bundle.cert_relay,
                    })
                } else {
                    None
                };
                return Ok((zones, verified_bundle));
            }
        };

        let mut checked: HashSet<Hash> = HashSet::with_capacity(bundle.epochs.len());
        let mut verified_epochs: Vec<msg::Epoch> = Vec::new();

        for epoch in bundle.epochs {
            let root = epoch.tree.compute_root()
                .map_err(|e| MessageError::HandleProofMalformed {
                    handle: format!("*@{}", space),
                    reason: e.to_string(),
                })?;

            if checked.contains(&root) {
                return Err(MessageError::DuplicateEpoch {
                    space: space.to_string(),
                    root,
                });
            }
            checked.insert(root);

            // Determine sovereignty based on commitment
            let sovereignty = if epoch.tree.0.is_empty() {
                SovereigntyState::Dependent
            } else {
                let onchain = chain.ptrs.find_commitment(&space, root)
                    .map_err(|e| MessageError::PtrsProofMalformed { reason: e.to_string() })?
                    .ok_or_else(|| MessageError::CommitmentNotFound {
                        space: space.to_string(),
                        root,
                    })?;

                if onchain.block_height > verified_tip.onchain.block_height {
                    return Err(MessageError::EpochExceedsTip { space: space.to_string() });
                }

                self.sovereignty_for(onchain.block_height)
            };

            let mut verified_handles: Vec<msg::Handle> = Vec::new();

            for handle in epoch.handles {
                let subject = SName::join(&handle.name, &space)
                    .map_err(|_| MessageError::InvalidSubject {
                        subject: format!("{}@{}", handle.name, space),
                    })?;

                if !ctx.wants(&subject) {
                    continue;
                }

                let zone = if handle.signature.is_some() {
                    if root != verified_tip.onchain.state_root {
                        return Err(MessageError::TemporaryRequiresTip { handle: subject.to_string() });
                    }
                    verify_temporary_handle(anchor.height, &handle, &subject, &epoch.tree, target_zone)?
                } else {
                    verify_final_handle(anchor.height, &handle, &subject, &epoch.tree, &chain.ptrs, sovereignty)?
                };

                push_best_zone(ctx, &mut zones, zone);
                verified_handles.push(handle);
            }

            if !verified_handles.is_empty() {
                verified_epochs.push(msg::Epoch {
                    tree: epoch.tree,
                    handles: verified_handles,
                });
            }
        }

        // Build verified bundle if anything was verified
        let verified_bundle = if wants_root || !verified_epochs.is_empty() {
            Some(msg::Bundle {
                space,
                receipt: if receipt_verified { bundle.receipt } else { None },
                epochs: verified_epochs,
                cert_relay: bundle.cert_relay,
            })
        } else {
            None
        };

        Ok((zones, verified_bundle))
    }

    fn check_msg_anchor(
        &self,
        msg: &crate::msg::Message,
    ) -> Result<RootAnchor, MessageError> {
        let height = msg.anchor.height;

        if height < self.oldest_anchor {
            return Err(MessageError::AnchorStale {
                anchor: height,
                oldest: self.oldest_anchor,
            });
        }
        if height > self.newest_anchor {
            return Err(MessageError::AnchorAhead {
                anchor: height,
                tip: self.newest_anchor,
            });
        }

        let anchor = self.find_by_anchor(height)
            .ok_or(MessageError::NoAnchorAtHeight { anchor: height })?
            .clone();

        if msg.anchor.hash != anchor.block.hash {
            return Err(MessageError::AnchorHashMismatch {
                height,
                expected: anchor.block.hash.to_byte_array(),
                got: msg.anchor.hash.to_byte_array(),
            });
        }

        Ok(anchor)
    }

    fn check_msg_chain_proofs(
        &self,
        msg: &crate::msg::Message,
        anchor: &RootAnchor,
    ) -> Result<(), MessageError> {
        let spaces_root = msg.chain.spaces
            .compute_root()
            .map_err(|_| MessageError::SpacesRootMismatch {
                expected: anchor.spaces_root,
                got: [0u8; 32],
            })?;

        if spaces_root != anchor.spaces_root {
            return Err(MessageError::SpacesRootMismatch {
                expected: anchor.spaces_root,
                got: spaces_root,
            });
        }

        if let Some(expected) = anchor.ptrs_root {
            let ptrs_root = msg.chain.ptrs
                .compute_root()
                .map_err(|_| MessageError::PtrsRootMismatch {
                    expected: Some(expected),
                    got: [0u8; 32],
                })?;

            if ptrs_root != expected {
                return Err(MessageError::PtrsRootMismatch {
                    expected: Some(expected),
                    got: ptrs_root,
                });
            }
        }

        Ok(())
    }

    fn check_msg_duplicate_spaces(&self, msg: &crate::msg::Message) -> Result<(), MessageError> {
        use std::collections::HashSet;
        let mut seen: HashSet<&[u8]> = HashSet::new();
        for bundle in &msg.spaces {
            if !seen.insert(bundle.space.as_ref()) {
                return Err(MessageError::DuplicateSpace {
                    space: bundle.space.to_string(),
                });
            }
        }
        Ok(())
    }

    fn find_by_anchor(&self, anchor: u32) -> Option<&RootAnchor> {
        self.anchors.iter().find(|a| a.block.height == anchor)
    }

    /// Extract parent zone from chain proofs and set sovereignty based on commitment finality.
    fn extract_parent_zone(&self, anchor: &ChainAnchor, chain: &msg::ChainProof, bundle: &msg::Bundle) -> Result<Option<Zone>, MessageError> {
        let Some(spaceout) = chain.spaces.find_space(&bundle.space) else {
            return Err(MessageError::SpaceNotFound { space: bundle.space.to_string() })
        };
        let handle = SName::from_space(&bundle.space)
            .map_err(|_| MessageError::InvalidSubject { subject: bundle.space.to_string() })?;
        let mut z = Zone {
            anchor: anchor.height,
            sovereignty: SovereigntyState::Sovereign,
            handle,
            script_pubkey: Default::default(),
            data: None,
            offchain_data: None,
            delegate: ProvableOption::Unknown,
            commitment: ProvableOption::Unknown,
        };
        let Some(space) = spaceout.space else {
            return Err(MessageError::SpaceNotFound { space: bundle.space.to_string() });
        };

        z.data = space.data().map(|d| Bytes::new(d.to_vec()));
        z.script_pubkey = spaceout.script_pubkey.clone();

        // Extract delegate info
        if let Ok(delegate) = chain.ptrs.find_sptr(&z.script_pubkey) {
            match delegate {
                None => z.delegate = ProvableOption::Empty,
                Some(delegate) => {
                    if let Some(ptr) = delegate.sptr {
                        z.delegate = ProvableOption::Exists {
                            value: Delegate {
                                script_pubkey: delegate.script_pubkey,
                                data: ptr.data,
                            },
                        }
                    }
                }
            }
        }

        // Extract commitment and set sovereignty
        if let Ok(root) = chain.ptrs.get_latest_commitment_root(&bundle.space) {
            match root {
                None => z.commitment = ProvableOption::Empty,
                Some(root) => {
                    let commitment = chain.ptrs.find_commitment(&bundle.space, root);
                    if let Ok(Some(commitment)) = commitment {
                        z.sovereignty = self.sovereignty_for(commitment.block_height);
                        z.commitment = ProvableOption::Exists {
                            value: CommitmentInfo {
                                onchain: commitment,
                                receipt_hash: None,
                            }
                        };
                    }
                }
            }
        }

        Ok(Some(z))
    }
}

/// Verify a temporary handle certificate (exclusion proof + signature).
fn verify_temporary_handle(
    anchor_height: u32,
    handle: &msg::Handle,
    subject: &SName,
    epoch_tree: &cert::HandleSubtree,
    parent_zone: &Zone,
) -> Result<Zone, MessageError> {
    // Empty tree = nothing exists, otherwise check exclusion
    let exists = !epoch_tree.0.is_empty() && epoch_tree
        .contains_subspace(&handle.name, &handle.genesis_spk)
        .map_err(|e| MessageError::HandleProofMalformed {
            handle: subject.to_string(),
            reason: e.to_string(),
        })?;

    if exists {
        return Err(MessageError::HandleAlreadyExists { handle: subject.to_string() });
    }

    let signer = match &parent_zone.delegate {
        ProvableOption::Exists { value: delegate } => &delegate.script_pubkey,
        ProvableOption::Empty => &parent_zone.script_pubkey,
        ProvableOption::Unknown => {
            return Err(MessageError::ParentDelegateUnknown { handle: subject.to_string() });
        }
    };

    let zone = Zone {
        anchor: anchor_height,
        sovereignty: SovereigntyState::Dependent,
        handle: subject.clone(),
        script_pubkey: handle.genesis_spk.clone(),
        data: None,
        offchain_data: handle.data.clone(),
        delegate: ProvableOption::Unknown,
        commitment: ProvableOption::Unknown,
    };

    zone.verify_signature(
        handle.signature.as_ref().unwrap(),
        signer,
    ).map_err(|e| MessageError::SignatureInvalid {
        handle: zone.handle.to_string(),
        reason: e.to_string(),
    })?;

    // Verify offchain_data signature if present
    if zone.offchain_data.is_some() {
        zone.verify_offchain_data().map_err(|e| MessageError::OffchainDataInvalid {
            handle: zone.handle.to_string(),
            reason: e.to_string(),
        })?;
    }

    Ok(zone)
}

/// Verify a final handle certificate (inclusion proof + key rotation).
fn verify_final_handle(
    anchor_height: u32,
    handle: &msg::Handle,
    subject: &SName,
    epoch_tree: &cert::HandleSubtree,
    ptrs: &cert::PtrsSubtree,
    sovereignty: SovereigntyState,
) -> Result<Zone, MessageError> {
    if epoch_tree.0.is_empty() {
        return Err(MessageError::FinalCertRequiresTree { handle: subject.to_string() });
    }

    let included = epoch_tree
        .contains_subspace(&handle.name, &handle.genesis_spk)
        .map_err(|e| MessageError::HandleProofMalformed {
            handle: subject.to_string(),
            reason: e.to_string(),
        })?;

    if !included {
        return Err(MessageError::HandleNotFound { handle: subject.to_string() });
    }

    // Key rotation lookup
    let ptrout = ptrs
        .find_sptr(&handle.genesis_spk)
        .map_err(|e| MessageError::PtrsProofMalformed { reason: e.to_string() })?;

    let (spk, onchain_data) = match ptrout {
        Some(ptrout) => (
            ptrout.script_pubkey,
            ptrout.sptr.and_then(|sptr| sptr.data),
        ),
        None => (handle.genesis_spk.clone(), None),
    };

    let zone = Zone {
        anchor: anchor_height,
        sovereignty,
        handle: subject.clone(),
        script_pubkey: spk,
        data: onchain_data,
        offchain_data: handle.data.clone(),
        delegate: ProvableOption::Unknown,
        commitment: ProvableOption::Unknown,
    };

    // Verify offchain_data signature if present
    if zone.offchain_data.is_some() {
        zone.verify_offchain_data().map_err(|e| MessageError::OffchainDataInvalid {
            handle: zone.handle.to_string(),
            reason: e.to_string(),
        })?;
    }

    Ok(zone)
}

/// Error during message verification.
#[derive(Debug, Clone)]
pub enum MessageError {
    /// Message anchor is too old
    AnchorStale { anchor: u32, oldest: u32 },
    /// Message anchor is newer than our tip
    AnchorAhead { anchor: u32, tip: u32 },
    /// No anchor exists at this height
    NoAnchorAtHeight { anchor: u32 },
    /// Anchor hash doesn't match our known anchor at this height
    AnchorHashMismatch { height: u32, expected: Hash, got: Hash },
    /// Duplicate space in message bundles
    DuplicateSpace { space: String },
    /// Receipt journal could not be decoded
    MalformedReceipt { space: String, reason: String },
    /// Receipt space hash doesn't match the bundle's space
    ReceiptSpaceMismatch { space: String },
    /// Receipt policy IDs don't match expected values
    ReceiptPolicyMismatch { space: String },
    /// Spaces proof root doesn't match anchor
    SpacesRootMismatch { expected: Hash, got: Hash },
    /// Ptrs proof root doesn't match anchor
    PtrsRootMismatch { expected: Option<Hash>, got: Hash },
    /// Space not found in spaces proof
    SpaceNotFound { space: String },
    /// Commitment not found in ptrs proof
    CommitmentNotFound { space: String, root: Hash },
    /// Receipt required but not provided
    ReceiptRequired { space: String },
    /// Parent zone could not be extracted from proof
    ParentZoneRequired { space: String },
    /// Handle subtree proof is malformed
    HandleProofMalformed { handle: String, reason: String },
    /// Duplicate epoch root in bundle
    DuplicateEpoch { space: String, root: Hash },
    /// Epoch's commitment height exceeds the verified tip
    EpochExceedsTip { space: String },
    /// Subject name is invalid
    InvalidSubject { subject: String },
    /// Temporary certificate must prove against the tip state
    TemporaryRequiresTip { handle: String },
    /// Handle already exists when exclusion proof expected
    HandleAlreadyExists { handle: String },
    /// Parent delegate is unknown, cannot verify signature
    ParentDelegateUnknown { handle: String },
    /// Signature verification failed
    SignatureInvalid { handle: String, reason: String },
    /// Offchain data signature verification failed
    OffchainDataInvalid { handle: String, reason: String },
    /// Final certificate requires non-empty handle tree
    FinalCertRequiresTree { handle: String },
    /// Handle not found in handle tree
    HandleNotFound { handle: String },
    /// Ptrs proof is malformed
    PtrsProofMalformed { reason: String },
    /// ZK receipt verification failed
    ReceiptInvalid { space: String, reason: String },
    /// On-chain commitment doesn't match receipt
    CommitmentReceiptMismatch { space: String, field: &'static str },
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnchorStale { anchor, oldest } => {
                write!(f, "anchor {} is stale, oldest is {}", anchor, oldest)
            }
            Self::AnchorAhead { anchor, tip } => {
                write!(f, "anchor {} is ahead of tip {}", anchor, tip)
            }
            Self::NoAnchorAtHeight { anchor } => {
                write!(f, "no anchor at height {}", anchor)
            }
            Self::AnchorHashMismatch { height, expected, got } => {
                write!(
                    f,
                    "anchor hash mismatch at {}: expected {}, got {}",
                    height, hex::encode(expected), hex::encode(got)
                )
            }
            Self::DuplicateSpace { space } => {
                write!(f, "duplicate space in message: {}", space)
            }
            Self::MalformedReceipt { space, reason } => {
                write!(f, "malformed receipt for {}: {}", space, reason)
            }
            Self::ReceiptSpaceMismatch { space } => {
                write!(f, "receipt space mismatch for {}", space)
            }
            Self::ReceiptPolicyMismatch { space } => {
                write!(f, "receipt policy mismatch for {}", space)
            }
            Self::SpacesRootMismatch { expected, got } => {
                write!(
                    f,
                    "spaces root mismatch: expected {}, got {}",
                    hex::encode(expected), hex::encode(got)
                )
            }
            Self::PtrsRootMismatch { expected, got } => {
                write!(
                    f,
                    "ptrs root mismatch: expected {}, got {}",
                    expected.map(hex::encode).unwrap_or_else(|| "none".into()),
                    hex::encode(got)
                )
            }
            Self::SpaceNotFound { space } => {
                write!(f, "space {} not found in proof", space)
            }
            Self::CommitmentNotFound { space, root } => {
                write!(f, "commitment {} not found for {}", hex::encode(root), space)
            }
            Self::ReceiptRequired { space } => {
                write!(f, "receipt required for {}", space)
            }
            Self::ParentZoneRequired { space } => {
                write!(f, "parent zone required for {}", space)
            }
            Self::HandleProofMalformed { handle, reason } => {
                write!(f, "handle proof malformed for {}: {}", handle, reason)
            }
            Self::DuplicateEpoch { space, root } => {
                write!(f, "duplicate epoch {} for {}", hex::encode(root), space)
            }
            Self::EpochExceedsTip { space } => {
                write!(f, "epoch commitment exceeds tip for {}", space)
            }
            Self::InvalidSubject { subject } => {
                write!(f, "invalid subject: {}", subject)
            }
            Self::TemporaryRequiresTip { handle } => {
                write!(f, "temporary certificate requires tip for {}", handle)
            }
            Self::HandleAlreadyExists { handle } => {
                write!(f, "handle {} already exists", handle)
            }
            Self::ParentDelegateUnknown { handle } => {
                write!(f, "parent delegate unknown for {}", handle)
            }
            Self::SignatureInvalid { handle, reason } => {
                write!(f, "signature invalid for {}: {}", handle, reason)
            }
            Self::OffchainDataInvalid { handle, reason } => {
                write!(f, "offchain data invalid for {}: {}", handle, reason)
            }
            Self::FinalCertRequiresTree { handle } => {
                write!(f, "final certificate requires non-empty tree for {}", handle)
            }
            Self::HandleNotFound { handle } => {
                write!(f, "handle {} not found", handle)
            }
            Self::PtrsProofMalformed { reason } => {
                write!(f, "ptrs proof malformed: {}", reason)
            }
            Self::ReceiptInvalid { space, reason } => {
                write!(f, "receipt invalid for {}: {}", space, reason)
            }
            Self::CommitmentReceiptMismatch { space, field } => {
                write!(f, "commitment {} mismatch for {}", field, space)
            }
        }
    }
}

impl std::error::Error for MessageError {}


/// Push the better zone: if cached exists and is better, push cached; otherwise push the new zone.
fn push_best_zone(ctx: &msg::QueryContext, zones: &mut Vec<Zone>, zone: Zone) {
    let Some(cached) = ctx.get_zone(&zone.handle) else {
        zones.push(zone);
        return;
    };
    if !zone.is_better_than(cached).unwrap_or(false) {
        zones.push(cached.clone());
        return;
    }
    zones.push(zone);
}

/// Verify ZK receipt if the zone requires one.
/// Returns true if receipt was verified, false if not needed.
fn maybe_verify_receipt(
    zone: &mut Zone,
    receipt: Option<&risc0_zkvm::Receipt>,
    space: &SLabel,
    dev_mode: bool,
) -> Result<bool, MessageError> {
    let Some(ci) = zone.requires_receipt() else {
        return Ok(false);
    };
    let receipt = receipt.ok_or_else(|| MessageError::ReceiptRequired { space: space.to_string() })?;
    verify_receipt(ci, space, receipt, dev_mode)?;
    Ok(true)
}

/// Decode a receipt journal without verification.
fn decode_journal(
    receipt: &risc0_zkvm::Receipt,
    space: &SLabel,
) -> Result<libveritas_zk::guest::Commitment, MessageError> {
    receipt.journal.decode().map_err(|e| MessageError::MalformedReceipt {
        space: space.to_string(),
        reason: e.to_string(),
    })
}

fn serialize_option_hash<S>(
    hash: &Option<Hash>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match hash {
        Some(bytes) => {
            if serializer.is_human_readable() {
                serializer.serialize_some(&hex::encode(bytes))
            } else {
                serializer.serialize_some(bytes)
            }
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_option_hash<'de, D>(deserializer: D) -> Result<Option<Hash>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let opt: Option<String> = <Option<String> as Deserialize>::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let mut bytes = [0u8; 32];
                hex::decode_to_slice(&s, &mut bytes).map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
        }
    } else {
        let opt: Option<[u8; 32]> = <Option<[u8; 32]> as Deserialize>::deserialize(deserializer)?;
        Ok(opt)
    }
}


fn verify_zk_journal_matches_onchain(space: &SLabel, zk: &libveritas_zk::guest::Commitment, onchain: &spaces_ptr::Commitment) -> Result<(), MessageError> {
    let space_str = space.to_string();
    let space_hash = Sha256Hasher::hash(space.as_ref());
    if zk.space != space_hash {
        return Err(MessageError::ReceiptSpaceMismatch { space: space_str });
    }
    if zk.policy_fold != libveritas_methods::FOLD_ID || zk.policy_step != libveritas_methods::STEP_ID {
        return Err(MessageError::ReceiptPolicyMismatch { space: space_str });
    }
    if zk.final_root != onchain.state_root {
        return Err(MessageError::CommitmentReceiptMismatch { space: space_str.clone(), field: "state_root" });
    }
    if zk.rolling_hash != onchain.rolling_hash {
        return Err(MessageError::CommitmentReceiptMismatch { space: space_str, field: "rolling_hash" });
    }
    Ok(())
}

// Retrieve parent zone without zk verification
fn hash_receipt(receipt: &Receipt) -> Hash {
    Sha256Hasher::hash(
        &borsh::to_vec(receipt).unwrap_or_default()
    )
}
