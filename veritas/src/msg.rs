use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};
use spacedb::{NodeHasher, Sha256Hasher};
use spaces_protocol::bitcoin::{ScriptBuf, secp256k1};
use spaces_protocol::constants::ChainAnchor;
use spaces_protocol::slabel::SLabel;
use std::collections::HashMap;
use std::io::{Read, Write};

use crate::{MessageError, Zone};
use crate::cert::{Certificate, HandleSubtree, PtrsSubtree, Signature, SpacesSubtree, Witness};
use crate::records::{RawRecords, Record};
use crate::sname::{Label, NameLike, SName};

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
        self.zones
            .iter()
            .find(|z| z.handle.is_single_label() && z.handle.space().as_ref() == Some(space))
    }
}

/// A certificate message for verifying space ownership and handle bindings.
///
/// Contains a chain anchor, shared on-chain proofs, and per-space data.
/// Multiple spaces can share the same chain proofs for efficient batching.
#[derive(Clone)]
pub struct Message {
    /// Shared on-chain merkle proofs anchored to a specific block.
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

    pub fn set_delegate_offchain_data(&mut self, handle: &SName, data: OffchainData) {
        self.set_offchain_data_inner(handle, data, true)
    }

    pub fn set_offchain_data(&mut self, handle: &SName, data: OffchainData) {
        self.set_offchain_data_inner(handle, data, false)
    }

    fn set_offchain_data_inner(&mut self, handle: &SName, data: OffchainData, delegate: bool) {
        let (space, subspace) = match handle.label_count() {
            1 => (handle.space().unwrap(), None),
            2 => (handle.space().unwrap(), Some(handle.subspace().unwrap())),
            _ => return,
        };

        let Some(bundle) = self.spaces
            .iter_mut()
            .find(|b| b.space == space) else {
            return;
        };

        match subspace {
            None => match delegate {
                true => bundle.delegate_offchain_data = Some(data),
                false => bundle.offchain_data = Some(data),
            }
            Some(name) => {
                if let Some(handle) = bundle
                    .epochs
                    .iter_mut()
                    .flat_map(|e| e.handles.iter_mut())
                    .find(|h| h.name == name)
                {
                    handle.data = Some(data);
                }
            }
        }
    }

    pub fn try_from_certificates(
        chain: ChainProof,
        certs: Vec<Certificate>,
    ) -> Result<Self, MessageError> {
        let mut msg = Self {
            chain,
            spaces: vec![],
        };

        let mut bundles: HashMap<SLabel, Bundle> = HashMap::new();
        let mut root_certs = vec![];
        let mut leaf_certs = vec![];

        for cert in certs {
            match cert.subject.label_count() {
                1 => root_certs.push(cert),
                2 => leaf_certs.push(cert),
                _ => continue,
            }
        }
        for root in root_certs {
            let label = root.subject.space().unwrap();
            bundles.insert(
                label.clone(),
                Bundle {
                    space: label,
                    receipt: match root.witness {
                        Witness::Root { receipt } => receipt,
                        _ => continue,
                    },
                    epochs: vec![],
                    offchain_data: None,
                    delegate_offchain_data: None,
                },
            );
        }
        for leaf in leaf_certs {
            let root = leaf.subject.space().unwrap();
            let (genesis_spk, handles, signature) = match leaf.witness {
                Witness::Root { .. } => continue,
                Witness::Leaf { genesis_spk, handles, signature } =>
                (genesis_spk, handles, signature),
            };
            let Some(bundle) = bundles.get_mut(&root) else {
                continue;
            };
            let epoch_root = handles.compute_root().expect("todo bubble error");
            match bundle.epochs.iter_mut().find(|e| e.tree.compute_root().unwrap() == epoch_root) {
                Some(e) => {
                    let subtree = std::mem::replace(&mut e.tree, HandleSubtree::empty());
                    e.tree = subtree.merge(handles).expect("todo bubble error");
                    e.handles.push(Handle {
                        name: leaf.subject.subspace().unwrap(),
                        genesis_spk,
                        data: None,
                        signature,
                    });
                }
                None => bundle.epochs.push(Epoch {
                    tree: handles,
                    handles: vec![
                        Handle {
                            name: leaf.subject.subspace().unwrap(),
                            genesis_spk,
                            data: None,
                            signature,
                        }
                    ],
                })
            };

        }
        msg.spaces = bundles.into_values().collect();
        Ok(msg)
    }
}

/// On-chain merkle proofs anchored to a specific block.
#[derive(Clone)]
pub struct ChainProof {
    /// The block anchor these proofs are valid for.
    pub anchor: ChainAnchor,
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
    pub data: RawRecords,
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
        let data = self.data.as_bytes();
        let mut bytes = Vec::with_capacity(4 + data.len());
        bytes.extend_from_slice(&self.seq.to_le_bytes());
        bytes.extend_from_slice(data);
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
        let hash_a = Sha256Hasher::hash(self.data.as_bytes());
        let hash_b = Sha256Hasher::hash(other.data.as_bytes());
        if hash_a != hash_b {
            return hash_a > hash_b;
        }
        false
    }

    /// Create OffchainData from a record set and signature.
    pub fn from_record_set(rs: RecordSet, signature: Signature) -> Self {
        Self {
            seq: rs.seq,
            data: rs.data,
            signature,
        }
    }
}

/// Serialized records ready to be signed.
///
/// Holds a sequence number and deterministically serialized records.
/// Use [`id()`](RecordSet::id) to get the 32-byte hash to sign,
/// then pass to [`OffchainData::from_record_set()`] with the signature.
#[derive(Clone)]
pub struct RecordSet {
    seq: u32,
    data: RawRecords,
}

impl RecordSet {
    /// Create a new record set from a sequence number and key-value records.
    ///
    /// Records are sorted by key for deterministic serialization.
    pub fn new(seq: u32, records: &[Record]) -> Self {
        Self {
            seq,
            data: RawRecords::from_records(records),
        }
    }

    /// The signing bytes: `seq (LE u32) || RawRecords bytes`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let data = self.data.as_bytes();
        let mut bytes = Vec::with_capacity(4 + data.len());
        bytes.extend_from_slice(&self.seq.to_le_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    /// The 32-byte hash to sign (Spaces signed-message prefix + SHA256).
    pub fn id(&self) -> [u8; 32] {
        let msg = crate::hash_signable_message(&self.signing_bytes());
        *msg.as_ref()
    }
}

// Borsh implementations

impl BorshSerialize for Message {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.chain, writer)?;
        BorshSerialize::serialize(&self.spaces, writer)
    }
}

impl BorshDeserialize for Message {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let chain = ChainProof::deserialize_reader(reader)?;
        let spaces = Vec::<Bundle>::deserialize_reader(reader)?;
        Ok(Message { chain, spaces })
    }
}

impl ChainProof {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("chain proof serialization should not fail")
    }
}

impl BorshSerialize for ChainProof {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.anchor, writer)?;
        BorshSerialize::serialize(&self.spaces, writer)?;
        BorshSerialize::serialize(&self.ptrs, writer)
    }
}

impl BorshDeserialize for ChainProof {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let anchor = ChainAnchor::deserialize_reader(reader)?;
        let spaces = SpacesSubtree::deserialize_reader(reader)?;
        let ptrs = PtrsSubtree::deserialize_reader(reader)?;
        Ok(ChainProof { anchor, spaces, ptrs })
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
        Ok(Bundle {
            space,
            receipt,
            epochs,
            offchain_data,
            delegate_offchain_data,
        })
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
        Ok(Handle {
            name,
            genesis_spk,
            data,
            signature,
        })
    }
}

impl BorshSerialize for OffchainData {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.seq, writer)?;
        BorshSerialize::serialize(&self.data, writer)?;
        BorshSerialize::serialize(&self.signature, writer)
    }
}

impl BorshDeserialize for OffchainData {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let seq = u32::deserialize_reader(reader)?;
        let data = RawRecords::deserialize_reader(reader)?;
        let signature = Signature::deserialize_reader(reader)?;
        Ok(OffchainData {
            seq,
            data,
            signature,
        })
    }
}
