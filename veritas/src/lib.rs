use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spaces_protocol::bitcoin::{BlockHash, ScriptBuf};
use spaces_protocol::bitcoin::hashes::Hash as HashUtil;
use spaces_protocol::Bytes;
use libveritas_zk::guest::CommitmentKind;
use crate::cert::{Certificate, LeafKind, Witness};
use crate::sname::{NameLike, SName};

pub mod sname;
pub mod cert;

pub struct Veritas {
    tip: RootAnchor,
    spaces: HashMap<Hash, ChainAnchor>,
    ptrs: HashMap<Hash, ChainAnchor>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Zone {
    pub serial: u32,
    pub sovereign: bool,
    pub handle: SName,
    pub script_pubkey: ScriptBuf,
    pub data: Option<Bytes>,
    pub delegate: ProvableOption<Delegate>,
    pub state_root: ProvableOption<Hash>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Delegate {
    pub script_pubkey: ScriptBuf,
    pub data: Option<Bytes>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChainAnchor {
    pub hash: BlockHash,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootAnchor {
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub spaces_root: Hash,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_hash",
        deserialize_with = "deserialize_optional_hash"
    )]
    pub ptrs_root: Option<Hash>,
    pub block: ChainAnchor,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProvableOption<T> {
    Exists { value: T },
    Empty,
    Unknown,
}


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
        let mut v = Veritas {
            tip: RootAnchor {
                spaces_root: [0u8; 32],
                ptrs_root: None,
                block: ChainAnchor { hash: BlockHash::all_zeros(), height: 0 },
            },
            spaces: HashMap::with_capacity(anchors.len()),
            ptrs: HashMap::with_capacity(anchors.len()),
        };
        v.update(anchors)?;
        Ok(v)
    }

    pub fn update(&mut self, anchors: Vec<RootAnchor>) -> Result<(), AnchorError> {
        if !anchors.iter().rev().is_sorted_by_key(|a| a.block.height) {
            return Err(AnchorError::NotSorted);
        }
        if anchors.is_empty() {
            return Err(AnchorError::Empty);
        }
        self.tip = anchors[0].clone();
        for anchor in anchors {
            self.spaces.insert(anchor.spaces_root, anchor.block);
            if let Some(root) = anchor.ptrs_root {
                self.ptrs.insert(root, anchor.block);
            }
        }
        Ok(())
    }

    pub fn verify(&self, cert: Certificate, parent: Option<&Zone>) -> Result<Zone, VerifyError> {
        match cert.witness {
            Witness::Root { inclusion, ptrs, commitment } => {
                if parent.is_some() {
                    return Err(VerifyError::RootHasNoParent);
                }

                let root = inclusion
                    .compute_root()
                    .map_err(|_| VerifyError::MalformedSpaceProof)?;

                let anchor = self
                    .spaces
                    .get(&root)
                    .ok_or(VerifyError::UnknownSpaceAnchor { root })?;

                if !cert.subject.is_single_label() {
                    return Err(VerifyError::InvalidRootSubject);
                }

                let spaceout = inclusion.find_space(&cert.subject.space().expect("space"))
                    .ok_or(VerifyError::SpaceNotFound)?;

                let space = spaceout.space
                    .ok_or(VerifyError::MalformedSpaceProof)?;

                if space.name != cert.subject.space().expect("space") {
                    return Err(VerifyError::MalformedSpaceProof);
                }

                let mut zone = Zone {
                    serial: anchor.height,
                    sovereign: true,
                    handle: cert.subject,
                    script_pubkey: spaceout.script_pubkey,
                    data: space.data().map(|data| Bytes::new(data.to_vec())),
                    delegate: ProvableOption::Unknown,
                    state_root: ProvableOption::Unknown,
                };

                let Some(ptrs) = ptrs else {
                    return Ok(zone);
                };

                let ptrs_root = ptrs.compute_root()
                    .map_err(|_| VerifyError::MalformedPtrsProof)?;

                let ptrs_anchor = self
                    .ptrs
                    .get(&ptrs_root)
                    .ok_or(VerifyError::UnknownPtrsAnchor { root: ptrs_root })?;

                if ptrs_anchor != anchor {
                    return Err(VerifyError::AnchorMismatch);
                }

                if let Ok(delegate) = ptrs.find_sptr(&zone.script_pubkey) {
                    match delegate {
                        None => zone.delegate = ProvableOption::Empty,
                        Some(delegate) => if let Some(ptr) = delegate.sptr {
                            zone.delegate = ProvableOption::Exists {
                                value: Delegate {
                                    script_pubkey: delegate.script_pubkey,
                                    data: ptr.data,
                                },
                            }
                        }
                    }
                }

                let Some(commitment_receipt) = commitment else {
                    // Does it provably have no commitments?
                    match ptrs.has_commitments(&zone.handle.space().expect("space")) {
                        Ok(false) => zone.state_root = ProvableOption::Empty,
                        _ => zone.state_root = ProvableOption::Unknown,
                    };
                    return Ok(zone);
                };

                let zkc: libveritas_zk::guest::Commitment = commitment_receipt
                    .journal
                    .decode()
                    .map_err(|e| VerifyError::MalformedReceipt {
                        reason: e.to_string(),
                    })?;

                let space_hash = Sha256Hasher::hash(space.name.as_ref());
                if zkc.space != space_hash {
                    return Err(VerifyError::ReceiptSpaceMismatch {
                        expected: space_hash,
                        receipt: zkc.space,
                    });
                }

                if zkc.policy_fold != libveritas_methods::FOLD_ID || zkc.policy_step != libveritas_methods::STEP_ID {
                    return Err(VerifyError::ReceiptPolicyMismatch);
                }

                let onchain_commitment = ptrs
                    .find_commitment(&space.name, zkc.final_root)
                    .ok()
                    .flatten()
                    .ok_or(VerifyError::CommitmentNotFound)?;

                if onchain_commitment.state_root != zkc.final_root {
                    return Err(VerifyError::CommitmentReceiptMismatch {
                        field: "state_root",
                        expected: zkc.final_root,
                        got: onchain_commitment.state_root,
                    });
                }
                if onchain_commitment.history_hash != zkc.transcript {
                    return Err(VerifyError::CommitmentReceiptMismatch {
                        field: "history_hash",
                        expected: zkc.transcript,
                        got: onchain_commitment.history_hash,
                    });
                }

                let image_id = match zkc.kind {
                    CommitmentKind::Fold => libveritas_methods::FOLD_ID,
                    CommitmentKind::Step => libveritas_methods::STEP_ID,
                };

                commitment_receipt
                    .verify(image_id)
                    .map_err(|e| VerifyError::ReceiptInvalid {
                        reason: e.to_string(),
                    })?;
                zone.state_root = ProvableOption::Exists { value: zkc.final_root };
                Ok(zone)
            }
            Witness::Leaf { genesis_spk, kind } => {
                if cert.subject.label_count() != 2 {
                    return Err(VerifyError::InvalidLeafSubject);
                }

                let parent = parent.ok_or(VerifyError::LeafRequiresParent)?;

                // Verify handle belongs to parent's space
                if cert.subject.space() != parent.handle.space() {
                    return Err(VerifyError::HandleSpaceMismatch);
                }

                match &parent.state_root {
                    ProvableOption::Exists { value: state_root } => {
                        match kind {
                            LeafKind::Final { inclusion, key_rotation } => {
                                let offchain_root = inclusion.compute_root()
                                    .map_err(|_| VerifyError::MalformedHandleProof)?;
                                if offchain_root != *state_root {
                                    return Err(VerifyError::HandleNotAnchored {
                                        expected: *state_root,
                                        got: offchain_root,
                                    });
                                }

                                let ptrs_root = key_rotation.compute_root()
                                    .map_err(|_| VerifyError::MalformedPtrsProof)?;

                                let ptrs_anchor = self.ptrs.get(&ptrs_root)
                                    .ok_or(VerifyError::UnknownPtrsAnchor { root: ptrs_root })?;

                                if parent.serial != ptrs_anchor.height {
                                    return Err(VerifyError::AnchorMismatch);
                                }

                                if !inclusion.contains_subspace(&cert.subject.subspace().expect("subspace"), &genesis_spk)
                                    .ok()
                                    .unwrap_or(false)
                                {
                                    return Err(VerifyError::HandleNotFound);
                                }

                                let ptrout = key_rotation.find_sptr(&genesis_spk)
                                    .map_err(|_| VerifyError::MalformedPtrsProof)?;

                                let (spk, onchain_data) = match ptrout {
                                    Some(ptrout) => (
                                        ptrout.script_pubkey,
                                        ptrout.sptr.and_then(|sptr| sptr.data),
                                    ),
                                    None => (genesis_spk, None),
                                };

                                Ok(Zone {
                                    serial: parent.serial,
                                    sovereign: true,
                                    handle: cert.subject,
                                    script_pubkey: spk,
                                    data: onchain_data,
                                    delegate: ProvableOption::Unknown,
                                    state_root: ProvableOption::Unknown,
                                })
                            }
                            LeafKind::Temporary { exclusion, signature: _ } => {
                                if parent.serial != self.tip.block.height {
                                    return Err(VerifyError::TemporaryRequiresTip);
                                }

                                let offchain_state = exclusion
                                    .as_ref()
                                    .ok_or(VerifyError::TemporaryRequiresExclusion)?;

                                let offchain_root = offchain_state.compute_root()
                                    .map_err(|_| VerifyError::MalformedHandleProof)?;

                                if offchain_root != *state_root {
                                    return Err(VerifyError::HandleNotAnchored {
                                        expected: *state_root,
                                        got: offchain_root,
                                    });
                                }

                                // Verify exclusion
                                let exists = offchain_state
                                    .contains_subspace(&cert.subject.subspace().expect("subspace"), &genesis_spk)
                                    .map_err(|_| VerifyError::MalformedHandleProof)?;

                                if exists {
                                    return Err(VerifyError::HandleAlreadyExists);
                                }

                                let _zone = Zone {
                                    serial: parent.serial,
                                    sovereign: false,
                                    handle: cert.subject,
                                    script_pubkey: genesis_spk,
                                    data: None,
                                    delegate: ProvableOption::Unknown,
                                    state_root: ProvableOption::Unknown,
                                };

                                todo!("verify schnorr signature")
                            }
                        }
                    }
                    ProvableOption::Empty => {
                        // State root provably doesn't exist, so we can just verify the signature
                        match kind {
                            LeafKind::Temporary {  exclusion, signature: _ } => {
                                if exclusion.is_some() {
                                    return Err(VerifyError::UnexpectedOffchainState);
                                }

                                let _zone = Zone {
                                    serial: parent.serial,
                                    sovereign: false,
                                    handle: cert.subject,
                                    script_pubkey: genesis_spk,
                                    data: None,
                                    delegate: ProvableOption::Unknown,
                                    state_root: ProvableOption::Unknown,
                                };

                                todo!("verify schnorr signature")
                            }
                            LeafKind::Final { .. } => {
                                return Err(VerifyError::ParentHasNoCommitments);
                            }
                        }
                    }
                    ProvableOption::Unknown => {
                        return Err(VerifyError::ParentStateUnknown);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum VerifyError {
    /// Space on-chain proof is malformed, cannot compute root
    MalformedSpaceProof,
    /// Ptrs on-chain proof is malformed, cannot compute root
    MalformedPtrsProof,
    /// Space does not exist in the on-chain tree
    SpaceNotFound,
    /// Root certificate must have subject "self@spacename"
    InvalidRootSubject,
    /// Computed space root is not a recognized anchor
    UnknownSpaceAnchor { root: Hash },
    /// Computed ptrs root is not a recognized anchor
    UnknownPtrsAnchor { root: Hash },
    /// Spaces and ptrs proofs must be from the same block
    AnchorMismatch,
    /// Root certificates cannot have a parent
    RootHasNoParent,
    /// Leaf certificates must have a parent zone
    LeafRequiresParent,
    /// Leaf certificate must have exactly two labels (subspace@space)
    InvalidLeafSubject,
    /// ZK receipt journal could not be decoded
    MalformedReceipt { reason: String },
    /// Receipt was generated for a different space
    ReceiptSpaceMismatch { expected: Hash, receipt: Hash },
    /// Receipt policy IDs don't match expected values
    ReceiptPolicyMismatch,
    /// Commitment key not found in on-chain tree
    CommitmentNotFound,
    /// On-chain commitment values don't match receipt
    CommitmentReceiptMismatch { field: &'static str, expected: Hash, got: Hash },
    /// ZK receipt cryptographic verification failed
    ReceiptInvalid { reason: String },
    /// Handle off-chain proof is malformed, cannot compute root
    MalformedHandleProof,
    /// Handle proof doesn't anchor to the expected commitment root
    HandleNotAnchored { expected: Hash, got: Hash },
    /// Handle certificate references different space than parent zone
    HandleSpaceMismatch,
    /// Handle key not found in off-chain tree
    HandleNotFound,
    /// Parent zone has no commitments, cannot verify final certificate
    ParentHasNoCommitments,
    /// Parent zone state root is unknown, cannot verify leaf
    ParentStateUnknown,
    /// Temporary certificate requires proof from the tip
    TemporaryRequiresTip,
    /// Temporary certificate requires exclusion proof when state exists
    TemporaryRequiresExclusion,
    /// Cannot issue temporary certificate for existing handle
    HandleAlreadyExists,
    /// Temporary certificate provided off-chain state but parent has none
    UnexpectedOffchainState,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSpaceProof => write!(f, "space proof is malformed"),
            Self::MalformedPtrsProof => write!(f, "ptrs proof is malformed"),
            Self::SpaceNotFound => write!(f, "space not found in on-chain tree"),
            Self::InvalidRootSubject => write!(f, "root certificate must have subject 'self@spacename'"),
            Self::UnknownSpaceAnchor { root } => {
                write!(f, "unknown space anchor: {}", hex::encode(root))
            }
            Self::UnknownPtrsAnchor { root } => {
                write!(f, "unknown ptrs anchor: {}", hex::encode(root))
            }
            Self::AnchorMismatch => write!(f, "spaces and ptrs proofs are from different blocks"),
            Self::RootHasNoParent => write!(f, "root certificate cannot have a parent"),
            Self::LeafRequiresParent => write!(f, "leaf certificate requires a parent zone"),
            Self::InvalidLeafSubject => write!(f, "leaf certificate must have exactly two labels"),
            Self::MalformedReceipt { reason } => write!(f, "malformed receipt: {}", reason),
            Self::ReceiptSpaceMismatch { expected, receipt } => {
                write!(
                    f,
                    "receipt space mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(receipt)
                )
            }
            Self::ReceiptPolicyMismatch => write!(f, "receipt policy mismatch"),
            Self::CommitmentNotFound => write!(f, "commitment not found in tree"),
            Self::CommitmentReceiptMismatch { field, expected, got } => {
                write!(
                    f,
                    "commitment {} mismatch: expected {}, got {}",
                    field,
                    hex::encode(expected),
                    hex::encode(got)
                )
            }
            Self::ReceiptInvalid { reason } => write!(f, "invalid receipt: {}", reason),
            Self::MalformedHandleProof => write!(f, "handle proof is malformed"),
            Self::HandleNotAnchored { expected, got } => {
                write!(
                    f,
                    "handle not anchored: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(got)
                )
            }
            Self::HandleSpaceMismatch => write!(f, "handle space doesn't match parent zone"),
            Self::HandleNotFound => write!(f, "handle not found in off-chain tree"),
            Self::ParentHasNoCommitments => write!(f, "parent zone has no commitments"),
            Self::ParentStateUnknown => write!(f, "parent zone state root is unknown"),
            Self::TemporaryRequiresTip => write!(f, "temporary certificate requires proof from tip"),
            Self::TemporaryRequiresExclusion => {
                write!(f, "temporary certificate requires exclusion proof")
            }
            Self::HandleAlreadyExists => write!(f, "cannot issue temporary certificate for existing handle"),
            Self::UnexpectedOffchainState => {
                write!(f, "temporary certificate has off-chain state but parent has none")
            }
        }
    }
}

impl std::error::Error for VerifyError {}


fn serialize_hash<S>(
    bytes: &spaces_protocol::hasher::Hash,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(bytes))
    } else {
        serializer.serialize_bytes(bytes)
    }
}

fn deserialize_hash<'de, D>(deserializer: D) -> Result<spaces_protocol::hasher::Hash, D::Error>
where
    D: Deserializer<'de>,
{
    let mut bytes = [0u8; 32];
    if deserializer.is_human_readable() {
        let s = String::deserialize(deserializer)?;
        hex::decode_to_slice(s, &mut bytes).map_err(serde::de::Error::custom)?;
    } else {
        spaces_protocol::hasher::Hash::deserialize(deserializer)?;
    }
    Ok(bytes)
}

fn serialize_optional_hash<S>(
    bytes: &Option<spaces_protocol::hasher::Hash>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match bytes {
        Some(b) => serialize_hash(b, serializer),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_hash<'de, D>(deserializer: D) -> Result<Option<spaces_protocol::hasher::Hash>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|s| {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(s, &mut bytes).map_err(serde::de::Error::custom)?;
            Ok(bytes)
        })
        .transpose()
}