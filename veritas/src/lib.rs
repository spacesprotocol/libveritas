use crate::cert::{Certificate, KeyHash, Witness, Signature};
use borsh::{BorshDeserialize, BorshSerialize};
use libveritas_zk::guest::CommitmentKind;
use risc0_zkvm::{Receipt, VerifierContext};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spaces_protocol::bitcoin::hashes::{Hash as HashUtil, sha256, HashEngine};
use spaces_protocol::bitcoin::secp256k1::{self, XOnlyPublicKey};
use spaces_protocol::bitcoin::{ScriptBuf};
use spaces_protocol::sname::{SName};
use spaces_protocol::constants::SPACES_SIGNED_MSG_PREFIX;
use spaces_protocol::slabel::SLabel;
use spaces_nums::constants::COMMITMENT_FINALITY_INTERVAL;
use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Write};
use spacedb::subtree::SubTree;
use spaces_nums::RootAnchor;

pub mod cert;
pub mod msg;
pub mod constants;
pub mod builder;
pub mod names;

pub use sip7;
use spaces_nums::num_id::NumId;
pub use spaces_protocol;

/// Verification option flags (combine with bitwise OR).
pub const VERIFY_DEFAULT: u32 = 0;
pub const VERIFY_DEV_MODE: u32 = 1 << 0;
pub const VERIFY_ENABLE_SNARK: u32 = 1 << 1;

/// Result of verifying a message.
///
/// Contains the verified zones and the original message data.
/// The message can be used to construct certificates for storage.
pub struct VerifiedMessage {
    pub root_id: [u8; 32],
    pub zones: Vec<Zone>,
    pub message: msg::Message,
}

impl VerifiedMessage {
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
                    let subject = SName::join(&h.name, &bundle.subject).ok()?;

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
            let root_handle = SName::from_space(&bundle.subject);
            if self.zones.iter().any(|z| z.canonical == root_handle) {
                return Some(Certificate::new(
                    root_handle,
                    Witness::Root {
                        receipt: bundle.receipt.clone(),
                    },
                ));
            }
        }
    }
}

#[derive(Clone)]
pub struct Veritas {
    anchors: Vec<RootAnchor>,
    oldest_anchor: u32,
    newest_anchor: u32,
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
    /// Human-readable name (e.g., "nested1.alice@bitcoin").
    /// Same as `canonical` when the handle has no numeric space.
    pub handle: SName,
    /// Canonical on-chain form (e.g., "nested1#800-12-12").
    pub canonical: SName,
    /// Set if this zone has a num alias.
    pub alias: Option<SLabel>,
    /// The current script pubkey that controls this handle.
    pub script_pubkey: ScriptBuf,
    /// Verified off-chain records from the handle owner.
    pub records: sip7::RecordSet,
    /// Optional on-chain data associated with the handle.
    pub fallback_records: sip7::RecordSet,
    /// Delegate information if the handle has delegated signing authority.
    pub delegate: ProvableOption<Delegate>,
    /// Commitment information including state root and finality status.
    pub commitment: ProvableOption<CommitmentInfo>,
    /// The numeric id for this zone:
    /// For spaces, its None.
    /// For handles, derived from their genesis spk
    /// For numerics, it's their num id
    pub num_id: Option<NumId>,
}


/// Information about a space's commitment state.
#[derive(Clone, Serialize, Deserialize)]
pub struct CommitmentInfo {
    /// The on-chain commitment data.
    pub onchain: spaces_nums::Commitment,
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
            onchain: spaces_nums::Commitment {
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
    /// Verified off-chain records from the delegate.
    pub records: sip7::RecordSet,
    pub fallback_records: sip7::RecordSet,
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
        BorshSerialize::serialize(&self.fallback_records.as_slice().to_vec(), writer)?;
        BorshSerialize::serialize(&self.records.as_slice().to_vec(), writer)
    }
}

impl BorshDeserialize for Delegate {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let spk_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        let fallback_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        let records_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        Ok(Delegate {
            script_pubkey: ScriptBuf::from_bytes(spk_bytes),
            fallback_records: sip7::RecordSet::new(fallback_bytes),
            records: sip7::RecordSet::new(records_bytes),
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
        let onchain = spaces_nums::Commitment::deserialize_reader(reader)?;
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
        BorshSerialize::serialize(&self.canonical, writer)?;
        BorshSerialize::serialize(&self.handle, writer)?;
        BorshSerialize::serialize(&self.alias, writer)?;
        BorshSerialize::serialize(&self.script_pubkey.as_bytes().to_vec(), writer)?;
        BorshSerialize::serialize(&self.fallback_records.as_slice().to_vec(), writer)?;
        BorshSerialize::serialize(&self.records.as_slice().to_vec(), writer)?;
        BorshSerialize::serialize(&self.delegate, writer)?;
        BorshSerialize::serialize(&self.commitment, writer)?;
        BorshSerialize::serialize(&self.num_id, writer)
    }
}

impl BorshDeserialize for Zone {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let anchor = u32::deserialize_reader(reader)?;
        let sovereignty = SovereigntyState::deserialize_reader(reader)?;
        let canonical = SName::deserialize_reader(reader)?;
        let handle = SName::deserialize_reader(reader)?;
        let alias = Option::<SLabel>::deserialize_reader(reader)?;
        let spk_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        let fallback_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        let records_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        let delegate: ProvableOption<Delegate> = ProvableOption::deserialize_reader(reader)?;
        let commitment: ProvableOption<CommitmentInfo> = ProvableOption::deserialize_reader(reader)?;

        let script_pubkey = ScriptBuf::from_bytes(spk_bytes);
        let num_id = Option::<NumId>::deserialize_reader(reader)?;
        Ok(Zone {
            anchor,
            sovereignty,
            handle,
            canonical,
            alias,
            script_pubkey,
            fallback_records: sip7::RecordSet::new(fallback_bytes),
            records: sip7::RecordSet::new(records_bytes),
            delegate,
            commitment,
            num_id,
        })
    }
}

/// Compute a deterministic id for a single root anchor.
pub fn compute_root_id(root: &RootAnchor) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(&root.block.hash[..]);
    engine.input(&root.block.height.to_le_bytes());
    engine.input(&root.spaces_root);
    engine.input(&root.nums_root.unwrap_or([0u8; 32]));
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// A compact representation of a set of trusted anchors.
#[derive(Clone)]
pub struct TrustSet {
    pub id: [u8; 32],
    pub roots: Vec<[u8; 32]>,
}

/// Compute a trust set from anchors.
pub fn compute_trust_set(anchors: &[RootAnchor]) -> TrustSet {
    let roots: Vec<[u8; 32]> = anchors.iter().map(compute_root_id).collect();
    let mut engine = sha256::Hash::engine();
    for r in &roots {
        engine.input(r);
    }
    TrustSet {
        id: sha256::Hash::from_engine(engine).to_byte_array(),
        roots,
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

/// Compare two record sets by seq then data hash (for Zone freshness comparison).
fn records_is_better(a: &sip7::RecordSet, b: &sip7::RecordSet) -> bool {
    let a_seq = a.seq().unwrap_or(0);
    let b_seq = b.seq().unwrap_or(0);
    if a_seq != b_seq {
        return a_seq > b_seq;
    }
    let hash_a = Sha256Hasher::hash(a.as_slice());
    let hash_b = Sha256Hasher::hash(b.as_slice());
    if hash_a != hash_b {
        return hash_a > hash_b;
    }
    false
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
    /// The `anchor` and `records` fields are zeroed out so delegate
    /// signatures remain valid across different anchor snapshots and
    /// don't include owner-signed records.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut zone = self.clone();
        zone.anchor = 0;
        zone.records = sip7::RecordSet::default();
        borsh::to_vec(&zone).expect("zone serialization should not fail")
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
    /// 4. Higher records seq (owner-signed records freshness, via sip7 Seq record)
    /// 5. Higher anchor (fresher chain state, tiebreaker only)
    ///
    /// Anchor is checked last to prevent attackers from downgrading cached
    /// state by sending messages with higher anchors but incomplete proofs.
    ///
    /// Returns an error if the zones are for different handles.
    pub fn is_better_than(&self, other: &Self) -> Result<bool, ZoneCompareError> {
        if self.canonical != other.canonical {
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
            (ProvableOption::Exists { value: a }, ProvableOption::Exists { value: b }) => {
                if !a.records.is_empty() || !b.records.is_empty() {
                    if a.records.is_empty() { return Ok(false); }
                    if b.records.is_empty() { return Ok(true); }
                    if records_is_better(&a.records, &b.records) {
                        return Ok(true);
                    }
                }
            }
            (ProvableOption::Exists { .. }, ProvableOption::Empty | ProvableOption::Unknown) => return Ok(true),
            (ProvableOption::Empty | ProvableOption::Unknown, ProvableOption::Exists { .. }) => return Ok(false),
            (ProvableOption::Empty, ProvableOption::Unknown) => return Ok(true),
            (ProvableOption::Unknown, ProvableOption::Empty) => return Ok(false),
            _ => {}
        }

        // Higher records seq = newer owner-signed records
        if !self.records.is_empty() || !other.records.is_empty() {
            if self.records.is_empty() { return Ok(false); }
            if other.records.is_empty() { return Ok(true); }
            if records_is_better(&self.records, &other.records) {
                return Ok(true);
            }
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

fn verify_receipt(ci: &mut CommitmentInfo, space: &SLabel, receipt: &Receipt, options: u32) -> Result<(), MessageError> {
    let space_str = space.to_string();
    let zkc = decode_journal(receipt, space)?;
    verify_zk_journal_matches_onchain(space, &zkc, &ci.onchain)?;
    let dev_mode = options & VERIFY_DEV_MODE != 0;
    let mut ctx = VerifierContext::default().with_dev_mode(dev_mode);
    if options & VERIFY_ENABLE_SNARK == 0 {
        if matches!(receipt.inner, risc0_zkvm::InnerReceipt::Groth16(_)) {
            return Err(MessageError::ReceiptInvalid {
                space: space_str,
                reason: "SNARK receipts require VERIFY_ENABLE_SNARK".to_string(),
            });
        }
        ctx.groth16_verifier_parameters = None;
    }
    let image_id = match zkc.kind {
        CommitmentKind::Fold => constants::FOLD_ID,
        CommitmentKind::Step => constants::STEP_ID,
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
    /// Sig record canonical name doesn't match expected
    SignerMismatch,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid schnorr public key"),
            Self::InvalidSignature => write!(f, "invalid signature format"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::SignerMismatch => write!(f, "sig record canonical name mismatch"),
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
    NotSorted,
}

impl fmt::Display for AnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSorted => write!(f, "anchors must be sorted by height in descending order"),
        }
    }
}

impl std::error::Error for AnchorError {}

impl Veritas {
    pub fn new() -> Self {
        Veritas {
            anchors: vec![],
            oldest_anchor: 0,
            newest_anchor: 0,
        }
    }

    pub fn with_anchors(mut self, anchors: Vec<RootAnchor>) -> Result<Self, AnchorError> {
        if !anchors.is_empty() {
            if !anchors.iter().rev().is_sorted_by_key(|a| a.block.height) {
                return Err(AnchorError::NotSorted);
            }
            self.newest_anchor = anchors[0].block.height;
            self.oldest_anchor = anchors.last().unwrap().block.height;
        }
        self.anchors = anchors;
        Ok(self)
    }

    pub fn oldest_anchor(&self) -> u32 {
        self.oldest_anchor
    }

    pub fn newest_anchor(&self) -> u32 {
        self.newest_anchor
    }

    pub fn compute_trust_set(&self) -> TrustSet {
        compute_trust_set(&self.anchors)
    }

    pub fn is_finalized(&self, commitment_height: u32) -> bool {
        let time_passed = self.newest_anchor.saturating_sub(commitment_height);
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

    /// Verify a message with default options.
    pub fn verify(&self, ctx: &msg::QueryContext, msg: crate::msg::Message) -> Result<VerifiedMessage, MessageError> {
        self.verify_with_options(ctx, msg, VERIFY_DEFAULT)
    }

    /// Verify a message with option flags.
    ///
    /// Flags can be combined with bitwise OR:
    /// - `VERIFY_DEFAULT` (0): standard verification
    /// - `VERIFY_DEV_MODE`: accept fake ZK receipts (for testing)
    /// - `VERIFY_ENABLE_SNARK`: allow Groth16 SNARK receipts (disabled by default)
    pub fn verify_with_options(
        &self,
        ctx: &msg::QueryContext,
        msg: crate::msg::Message,
        options: u32,
    ) -> Result<VerifiedMessage, MessageError> {
        let anchor = self.check_msg_anchor(&msg)?;
        self.check_msg_chain_proofs(&msg, &anchor)?;
        self.check_msg_duplicate_spaces(&msg)?;

        let mut zones = Vec::new();
        let mut verified_bundles = Vec::new();

        for bundle in msg.spaces {
            let (bundle_zones, verified_bundle) =
                self.verify_bundle(ctx, &msg.chain, options, bundle)?;
            zones.extend(bundle_zones);
            if let Some(vb) = verified_bundle {
                verified_bundles.push(vb);
            }
        }

        let resolver = names::NameResolver::from_zones(&zones);
        resolver.expand_zones(&mut zones);

        Ok(VerifiedMessage {
            root_id: compute_root_id(&anchor),
            zones,
            message: msg::Message {
                chain: msg.chain,
                spaces: verified_bundles,
            },
        })
    }


    fn verify_bundle(
        &self,
        ctx: &msg::QueryContext,
        chain: &msg::ChainProof,
        options: u32,
        bundle: msg::Bundle,
    ) -> Result<(Vec<Zone>, Option<msg::Bundle>), MessageError> {
        let space = bundle.subject.clone();
        let cached_parent = ctx.get_parent_zone(&space);
        let mut extracted = self.extract_parent_zone(chain, &bundle)?;

        let root_handle = SName::from_space(&space);

        let mut zones: Vec<Zone> = Vec::new();
        let mut receipt_verified = false;

        // Resolve which parent zone to use
        let target_zone: &Zone = match (&cached_parent, &mut extracted) {
            (Some(cached), Some(zone)) => {
                zone.update_receipt_cache(cached);
                if zone.is_better_than(cached).unwrap_or(false) {
                    receipt_verified = maybe_verify_receipt(zone, bundle.receipt.as_ref(), &space, options)?;
                    zone
                } else {
                    *cached
                }
            }
            (Some(cached), None) => *cached,
            (None, Some(zone)) => {
                receipt_verified = maybe_verify_receipt(zone, bundle.receipt.as_ref(), &space, options)?;
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
                        subject: space,
                        receipt: if receipt_verified { bundle.receipt } else { None },
                        epochs: vec![],
                        records: bundle.records,
                        delegate_records: bundle.delegate_records,
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
                let onchain = chain.nums.find_commitment(&space, root)
                    .map_err(|e| MessageError::NumsProofMalformed { reason: e.to_string() })?
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
                        return Err(MessageError::TemporaryRequiresTip {
                            handle: subject.to_string(),
                            tip: verified_tip.onchain.state_root,
                            got: root
                        });
                    }
                    verify_temporary_handle(chain.anchor.height, &handle, &subject, &epoch.tree, target_zone)?
                } else {
                    verify_final_handle(chain.anchor.height, &handle, &subject, &epoch.tree, &chain.nums, sovereignty)?
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
                subject: space,
                receipt: if receipt_verified { bundle.receipt } else { None },
                epochs: verified_epochs,
                records: bundle.records,
                delegate_records: bundle.delegate_records,
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
        let height = msg.chain.anchor.height;

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

        if msg.chain.anchor.hash != anchor.block.hash {
            return Err(MessageError::AnchorHashMismatch {
                height,
                expected: anchor.block.hash.to_byte_array(),
                got: msg.chain.anchor.hash.to_byte_array(),
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

        if let Some(expected) = anchor.nums_root {
            let nums_root = msg.chain.nums
                .compute_root()
                .map_err(|_| MessageError::NumsRootMismatch {
                    expected: Some(expected),
                    got: [0u8; 32],
                })?;

            if nums_root != expected {
                return Err(MessageError::NumsRootMismatch {
                    expected: Some(expected),
                    got: nums_root,
                });
            }
        }

        Ok(())
    }

    fn check_msg_duplicate_spaces(&self, msg: &crate::msg::Message) -> Result<(), MessageError> {
        use std::collections::HashSet;
        let mut seen: HashSet<&[u8]> = HashSet::new();
        for bundle in &msg.spaces {
            if !seen.insert(bundle.subject.as_ref()) {
                return Err(MessageError::DuplicateSpace {
                    space: bundle.subject.to_string(),
                });
            }
        }
        Ok(())
    }

    fn find_by_anchor(&self, anchor: u32) -> Option<&RootAnchor> {
        self.anchors.iter().find(|a| a.block.height == anchor)
    }

    /// Extract parent zone from chain proofs and set sovereignty based on commitment finality.
    fn extract_parent_zone(&self, chain: &msg::ChainProof, bundle: &msg::Bundle) -> Result<Option<Zone>, MessageError> {
        let mut num_id = None;
        let (spk, records) = if !bundle.subject.is_numeric() {
            let Some(spaceout) = chain.spaces.find_space(&bundle.subject) else {
                return Err(MessageError::SpaceNotFound { space: bundle.subject.to_string() })
            };
            let Some(space) = spaceout.space else {
                return Err(MessageError::SpaceNotFound { space: bundle.subject.to_string() });
            };
            let data = space.data()
                .filter(|d| !d.is_empty())
                .map(|d| sip7::RecordSet::new(d.to_vec()))
                .unwrap_or_default();
            (spaceout.script_pubkey, data)
        } else {
            let Some(numout) = chain.nums
                .find_numeric(&bundle.subject.clone().try_into().expect("numeric"))
                .ok().flatten() else {
                return Err(MessageError::NumericNotFound { numeric: bundle.subject.to_string() })
            };
            num_id = Some(numout.num.id);
            let data = numout.num.data
                .filter(|d| !d.is_empty())
                .map(|d| sip7::RecordSet::new(d.to_vec()))
                .unwrap_or_default();
            (numout.script_pubkey, data)
        };

        let handle = SName::from_space(&bundle.subject);

        let mut z = Zone {
            anchor: chain.anchor.height,
            sovereignty: SovereigntyState::Sovereign,
            canonical: handle.clone(),
            handle,
            alias: None,
            script_pubkey: spk,
            fallback_records: records,
            records: sip7::RecordSet::default(),
            delegate: ProvableOption::Unknown,
            commitment: ProvableOption::Unknown,
            num_id,
        };

        // Verify records signature if present
        if let Some(records) = &bundle.records {
            msg::verify_records(records, &z.script_pubkey, &z.canonical)
                .map_err(|e| MessageError::RecordsInvalid {
                    handle: z.handle.to_string(),
                    reason: e.to_string(),
                })?;
            z.records = records.clone();
        }

        // Extract delegate info
        if let Ok(delegate) = chain.nums.find_num(&z.script_pubkey) {
            match delegate {
                None => z.delegate = ProvableOption::Empty,
                Some(delegate) => {
                    let mut delegate_records = sip7::RecordSet::default();
                    if let Some(records) = &bundle.delegate_records {
                        msg::verify_records(records, &delegate.script_pubkey, &z.canonical)
                            .map_err(|e| MessageError::RecordsInvalid {
                                handle: z.handle.to_string(),
                                reason: e.to_string(),
                            })?;
                        delegate_records = records.clone();
                    }
                    z.delegate = ProvableOption::Exists {
                        value: Delegate {
                            script_pubkey: delegate.script_pubkey,
                            fallback_records: delegate.num.data
                                .filter(|d| !d.is_empty())
                                .map(|d| sip7::RecordSet::new(d.to_vec()))
                                .unwrap_or_default(),
                            records: delegate_records,
                        },
                    }
                }
            }
        }

        // Extract commitment and set sovereignty
        if let Ok(root) = chain.nums.get_latest_commitment_root(&bundle.subject) {
            match root {
                None => z.commitment = ProvableOption::Empty,
                Some(root) => {
                    let commitment = chain.nums.find_commitment(&bundle.subject, root);
                    if let Ok(Some(commitment)) = commitment {
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

    let mut verified_records = sip7::RecordSet::default();
    if let Some(records) = &handle.records {
        msg::verify_records(records, &handle.genesis_spk, &subject)
            .map_err(|e| MessageError::RecordsInvalid {
                handle: subject.to_string(),
                reason: e.to_string(),
            })?;
        verified_records = records.clone();
    }

    let num_id = Some(NumId::from_spk::<KeyHash>(handle.genesis_spk.clone()));
    let zone = Zone {
        anchor: anchor_height,
        sovereignty: SovereigntyState::Dependent,
        canonical: subject.clone(),
        handle: subject.clone(),
        alias: None,
        script_pubkey: handle.genesis_spk.clone(),
        fallback_records: sip7::RecordSet::default(),
        records: verified_records,
        delegate: ProvableOption::Unknown,
        commitment: ProvableOption::Unknown,
        num_id,
    };

    zone.verify_signature(
        handle.signature.as_ref().unwrap(),
        signer,
    ).map_err(|e| MessageError::SignatureInvalid {
        handle: zone.handle.to_string(),
        reason: e.to_string(),
    })?;

    Ok(zone)
}

/// Verify a final handle certificate (inclusion proof + key rotation).
fn verify_final_handle(
    anchor_height: u32,
    handle: &msg::Handle,
    subject: &SName,
    epoch_tree: &cert::HandleSubtree,
    nums: &cert::NumsSubtree,
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
    let numout = nums
        .find_num(&handle.genesis_spk)
        .map_err(|e| MessageError::NumsProofMalformed { reason: e.to_string() })?;

    let (num_id, spk, onchain_data, alias) = match numout {
        Some(numout) => (
            numout.num.id,
            numout.script_pubkey,
            numout.num.data
                .filter(|d| !d.is_empty())
                .map(|d| sip7::RecordSet::new(d.to_vec()))
                .unwrap_or_default(),
            Some(numout.num.name.to_slabel())
        ),
        None => (NumId::from_spk::<KeyHash>(handle.genesis_spk.clone()), handle.genesis_spk.clone(), sip7::RecordSet::default(), None),
    };

    let mut verified_records = sip7::RecordSet::default();
    if let Some(records) = &handle.records {
        msg::verify_records(records, &spk, &subject)
            .map_err(|e| MessageError::RecordsInvalid {
                handle: subject.to_string(),
                reason: e.to_string(),
            })?;
        verified_records = records.clone();
    }

    let zone = Zone {
        anchor: anchor_height,
        sovereignty,
        canonical: subject.clone(),
        handle: subject.clone(),
        alias,
        script_pubkey: spk,
        fallback_records: onchain_data,
        records: verified_records,
        delegate: ProvableOption::Unknown,
        commitment: ProvableOption::Unknown,
        num_id: Some(num_id),
    };

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
    /// Receipt policy IDs don't match expected values
    ReceiptPolicyMismatch { space: String },
    /// Spaces proof root doesn't match anchor
    SpacesRootMismatch { expected: Hash, got: Hash },
    /// Nums proof root doesn't match anchor
    NumsRootMismatch { expected: Option<Hash>, got: Hash },
    /// Space not found in spaces proof
    SpaceNotFound { space: String },
    /// Numeric space not found in nums proof
    NumericNotFound { numeric: String },
    /// Commitment not found in nums proof
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
    TemporaryRequiresTip { handle: String, tip: Hash, got: Hash },
    /// Handle already exists when exclusion proof expected
    HandleAlreadyExists { handle: String },
    /// Parent delegate is unknown, cannot verify signature
    ParentDelegateUnknown { handle: String },
    /// Signature verification failed
    SignatureInvalid { handle: String, reason: String },
    /// Offchain data signature verification failed
    RecordsInvalid { handle: String, reason: String },
    /// Final certificate requires non-empty handle tree
    FinalCertRequiresTree { handle: String },
    /// Handle not found in handle tree
    HandleNotFound { handle: String },
    /// Nums proof is malformed
    NumsProofMalformed { reason: String },
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
            Self::NumsRootMismatch { expected, got } => {
                write!(
                    f,
                    "nums root mismatch: expected {}, got {}",
                    expected.map(hex::encode).unwrap_or_else(|| "none".into()),
                    hex::encode(got)
                )
            }
            Self::SpaceNotFound { space } => {
                write!(f, "space {} not found in proof", space)
            }
            Self::NumericNotFound { numeric } => {
                write!(f, "numeric space {} not found in proof", numeric)
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
            Self::TemporaryRequiresTip { handle, tip, got } => {
                write!(
                    f, "Temporary handle {} verifies against {} but requires tip {}",
                    handle, hex::encode(got), hex::encode(tip)
                )
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
            Self::RecordsInvalid { handle, reason } => {
                write!(f, "records invalid for {}: {}", handle, reason)
            }
            Self::FinalCertRequiresTree { handle } => {
                write!(f, "final certificate requires non-empty tree for {}", handle)
            }
            Self::HandleNotFound { handle } => {
                write!(f, "handle {} not found", handle)
            }
            Self::NumsProofMalformed { reason } => {
                write!(f, "nums proof malformed: {}", reason)
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
    let Some(cached) = ctx.get_zone(&zone.canonical) else {
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
    options: u32,
) -> Result<bool, MessageError> {
    let Some(ci) = zone.requires_receipt() else {
        return Ok(false);
    };
    let receipt = receipt.ok_or_else(|| MessageError::ReceiptRequired { space: space.to_string() })?;
    verify_receipt(ci, space, receipt, options)?;
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

fn verify_zk_journal_matches_onchain(space: &SLabel, zk: &libveritas_zk::guest::Commitment, onchain: &spaces_nums::Commitment) -> Result<(), MessageError> {
    let space_str = space.to_string();
    if zk.policy_fold != constants::FOLD_ID || zk.policy_step != constants::STEP_ID {
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
