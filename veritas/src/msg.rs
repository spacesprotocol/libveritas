use std::io::{Read, Write};
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};
use spacedb::{NodeHasher, Sha256Hasher};
use spaces_protocol::Bytes;
use spaces_protocol::bitcoin::{secp256k1, ScriptBuf};
use spaces_protocol::constants::ChainAnchor;
use spaces_protocol::slabel::SLabel;

use crate::cert::{HandleSubtree, PtrsSubtree, Signature, SpacesSubtree};
use crate::sname::{Label, NameLike, SName};
use crate::Zone;

/// Context for a verification query.
///
/// Contains the handles to verify and any zones the caller knows about.
/// Zones are used for parent lookups and `is_better_than` comparison.
pub struct QueryContext {
    /// Handles to verify. Empty = verify all handles in the message.
    pub requests: Vec<SName>,
    /// Known zones - parents, leaves, any zones the caller has.
    pub zones: Vec<Zone>,
}

impl QueryContext {
    /// Create an empty context (verify all, no prior zones).
    pub fn new() -> Self {
        Self {
            requests: vec![],
            zones: vec![],
        }
    }

    /// Create a context from known zones (verify all).
    pub fn from_zones(zones: Vec<Zone>) -> Self {
        Self {
            requests: vec![],
            zones,
        }
    }

    /// Add a handle to the request list.
    pub fn add_request(&mut self, handle: SName) {
        if !self.requests.iter().any(|h| h == &handle) {
            self.requests.push(handle);
        }
    }

    /// Add a zone to the context. Replaces if handle already exists.
    pub fn add_zone(&mut self, zone: Zone) {
        if let Some(existing) = self.zones.iter_mut().find(|z| z.handle == zone.handle) {
            *existing = zone;
        } else {
            self.zones.push(zone);
        }
    }

    /// Check if a handle is requested (empty requests = want all).
    pub fn wants(&self, handle: &SName) -> bool {
        self.requests.is_empty() || self.requests.iter().any(|h| h == handle)
    }

    /// Get a zone by exact handle.
    pub fn get_zone(&self, handle: &SName) -> Option<&Zone> {
        self.zones.iter().find(|z| &z.handle == handle)
    }

    /// Get the parent (root) zone for a space.
    ///
    /// For `alice@bitcoin`, this finds the `@bitcoin` zone.
    pub fn get_parent_zone(&self, space: &SLabel) -> Option<&Zone> {
        self.zones.iter().find(|z| {
            z.handle.is_single_label() && z.handle.space().as_ref() == Some(space)
        })
    }
}

/// A certificate message for verifying space ownership and handle bindings.
///
/// Contains a chain anchor, shared on-chain proofs, and per-space data.
/// Multiple spaces can share the same chain proofs for efficient batching.
#[derive(Clone)]
pub struct Message {
    /// The block anchor this message is valid for.
    pub anchor: ChainAnchor,
    /// Shared on-chain merkle proofs (spaces and ptrs trees).
    pub chain: ChainProof,
    /// Per-space records. Uniqueness enforced during verification.
    pub spaces: Vec<Bundle>,
}

impl Message {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("message serialization should not fail")
    }
}

/// On-chain merkle proofs shared across all spaces in the message.
#[derive(Clone)]
pub struct ChainProof {
    /// Proof from the spaces tree (space existence, ownership).
    pub spaces: SpacesSubtree,
    /// Proof from the ptrs tree (delegation, commitments, key rotation).
    pub ptrs: PtrsSubtree,
}

/// Data for a single space, including its tip receipt and handle epochs.
#[derive(Clone)]
pub struct Bundle {
    /// The space this record is for (e.g., "@bitcoin").
    pub space: SLabel,
    /// ZK receipt proving the tip epoch. `None` if the tip is finalized
    /// and the verifier's cache covers it, or for first-commitment spaces.
    /// When present, the journal decodes to the tip's final_root.
    pub receipt: Option<Receipt>,
    /// Handle epochs for this space. Each epoch corresponds to a committed
    /// state root. The tip epoch (if handles are being proven against it)
    /// should have `tree.compute_root()` matching the receipt's final_root
    /// or the on-chain tip from the chain proof.
    pub epochs: Vec<Epoch>,
    /// Off-chain data signed by the space owner.
    pub offchain_data: Option<OffchainData>,
    /// Off-chain data signed by the delegate.
    pub delegate_offchain_data: Option<OffchainData>,
}

impl Bundle {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("bundle serialization should not fail")
    }
}

/// A snapshot of the handle tree at a specific commitment.
///
/// The epoch's root is derived via `tree.compute_root()` and verified
/// against the chain proof. Block height is looked up from the on-chain
/// commitment data, not stored here.
#[derive(Clone)]
pub struct Epoch {
    /// Merkle proof for handles in this epoch (inclusion or exclusion).
    pub tree: HandleSubtree,
    /// Handles being proven in this epoch.
    pub handles: Vec<Handle>,
}

/// A handle being proven within an epoch.
#[derive(Clone, Serialize, Deserialize)]
pub struct Handle {
    /// The handle name (e.g., "alice" for "alice@bitcoin").
    pub name: Label,
    /// The genesis script pubkey the handle was initialized with.
    pub genesis_spk: ScriptBuf,
    /// Off-chain data signed by the handle owner
    pub data: Option<OffchainData>,
    /// Signature from the delegate for temporary certificates.
    /// `None` for final certificates (handle committed to tree).
    pub signature: Option<Signature>,
}

impl Handle {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("handle serialization should not fail")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OffchainData {
    pub seq: u32,
    pub data: Bytes,
    pub signature: Signature,
}

impl OffchainData {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("offchain data serialization should not fail")
    }

    /// Returns the bytes to sign: seq || data
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.data.as_slice().len());
        bytes.extend_from_slice(&self.seq.to_le_bytes());
        bytes.extend_from_slice(self.data.as_slice());
        bytes
    }

    /// Verify the signature against the given script pubkey.
    pub fn verify(&self, script_pubkey: &ScriptBuf) -> Result<(), crate::SignatureError> {
        use secp256k1::XOnlyPublicKey;
        let script_bytes = script_pubkey.as_bytes();
        if script_bytes.len() != secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE + 2 {
            return Err(crate::SignatureError::InvalidPublicKey);
        }
        let pubkey = XOnlyPublicKey::from_slice(&script_bytes[2..])
            .map_err(|_| crate::SignatureError::InvalidPublicKey)?;
        let msg = crate::hash_signable_message(&self.signing_bytes());
        let sig = secp256k1::schnorr::Signature::from_slice(&self.signature.0)
            .map_err(|_| crate::SignatureError::InvalidSignature)?;
        secp256k1::Secp256k1::verification_only()
            .verify_schnorr(&sig, &msg, &pubkey)
            .map_err(|_| crate::SignatureError::VerificationFailed)
    }

    pub fn is_better_than(&self, other: &Self) -> bool {
        if self.seq != other.seq {
            return self.seq > other.seq;
        }
        // Same seq, compare data hash for deterministic tiebreaker
        let hash_a = Sha256Hasher::hash(self.data.as_slice());
        let hash_b = Sha256Hasher::hash(other.data.as_slice());
        if hash_a != hash_b {
            return hash_a > hash_b;
        }
        false
    }
}

// Borsh implementations

impl BorshSerialize for Message {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.anchor, writer)?;
        BorshSerialize::serialize(&self.chain, writer)?;
        BorshSerialize::serialize(&self.spaces, writer)
    }
}

impl BorshDeserialize for Message {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let anchor = ChainAnchor::deserialize_reader(reader)?;
        let chain = ChainProof::deserialize_reader(reader)?;
        let spaces = Vec::<Bundle>::deserialize_reader(reader)?;
        Ok(Message { anchor, chain, spaces })
    }
}

impl BorshSerialize for ChainProof {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.spaces, writer)?;
        BorshSerialize::serialize(&self.ptrs, writer)
    }
}

impl BorshDeserialize for ChainProof {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let spaces = SpacesSubtree::deserialize_reader(reader)?;
        let ptrs = PtrsSubtree::deserialize_reader(reader)?;
        Ok(ChainProof { spaces, ptrs })
    }
}

impl BorshSerialize for Bundle {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.space, writer)?;
        BorshSerialize::serialize(&self.receipt, writer)?;
        BorshSerialize::serialize(&self.epochs, writer)?;
        BorshSerialize::serialize(&self.offchain_data, writer)?;
        BorshSerialize::serialize(&self.delegate_offchain_data, writer)
    }
}

impl BorshDeserialize for Bundle {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let space = SLabel::deserialize_reader(reader)?;
        let receipt = Option::<Receipt>::deserialize_reader(reader)?;
        let epochs = Vec::<Epoch>::deserialize_reader(reader)?;
        let offchain_data = Option::<OffchainData>::deserialize_reader(reader)?;
        let delegate_offchain_data = Option::<OffchainData>::deserialize_reader(reader)?;
        Ok(Bundle { space, receipt, epochs, offchain_data, delegate_offchain_data })
    }
}

impl BorshSerialize for Epoch {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.tree, writer)?;
        BorshSerialize::serialize(&self.handles, writer)
    }
}

impl BorshDeserialize for Epoch {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let tree = HandleSubtree::deserialize_reader(reader)?;
        let handles = Vec::<Handle>::deserialize_reader(reader)?;
        Ok(Epoch { tree, handles })
    }
}

impl BorshSerialize for Handle {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.name, writer)?;
        BorshSerialize::serialize(&self.genesis_spk.as_bytes().to_vec(), writer)?;
        BorshSerialize::serialize(&self.data, writer)?;
        BorshSerialize::serialize(&self.signature, writer)
    }
}

impl BorshDeserialize for Handle {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let name = Label::deserialize_reader(reader)?;
        let spk_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        let genesis_spk = ScriptBuf::from_bytes(spk_bytes);
        let data = Option::<OffchainData>::deserialize_reader(reader)?;
        let signature = Option::<Signature>::deserialize_reader(reader)?;
        Ok(Handle { name, genesis_spk, data, signature })
    }
}

impl BorshSerialize for OffchainData {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.seq, writer)?;
        BorshSerialize::serialize(&self.data.to_vec(), writer)?;
        BorshSerialize::serialize(&self.signature, writer)
    }
}

impl BorshDeserialize for OffchainData {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let seq = u32::deserialize_reader(reader)?;
        let data = Vec::<u8>::deserialize_reader(reader)?;
        let signature = Signature::deserialize_reader(reader)?;
        Ok(OffchainData { seq, data: Bytes::new(data), signature })
    }
}
