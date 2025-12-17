use std::fmt;
use std::io::{Read, Write};
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spacedb::subtree::{SubTree, SubtreeIter};
use spacedb::encode::SubTreeEncoder;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::Receipt;
use spaces_protocol::bitcoin::ScriptBuf;
use spaces_protocol::hasher::{KeyHasher, OutpointKey};
use spaces_protocol::slabel::SLabel;
use spaces_protocol::SpaceOut;
use spaces_ptr::{Commitment, CommitmentKey, PtrOut, RegistryKey};
use spaces_ptr::sptr::Sptr;
use crate::sname::{Label, SName};

// Maximum buffer size for SubTree serialization (8 KB should be sufficient)
const SUBTREE_ENCODE_BUFFER_SIZE: usize = 1024 * 8;

/// A certificate proving ownership for a space handle.
///
/// A certificate binds a [`subject`](Certificate::subject) (the space name being certified)
/// to a [`witness`](Certificate::witness) that proves the certificate's validity through
/// on-chain inclusion proofs and any off-chain delegation chains.
///
/// # Verification
///
/// Certificates form a chain of trust:
/// - **Root certificates** prove a space exists on-chain via merkle inclusion proofs
/// - **Leaf certificates** prove delegation from a root space to a subspace handle
///
/// # Example
///
/// For `alice@bitcoin`:
/// - A `Root` witness proves `bitcoin` is registered on-chain
/// - For `keys@bitcoin`, a `Leaf` witness proves delegation from `bitcoin`
#[derive(Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// The space handle this certificate attests to.
    pub subject: SName,
    /// The proof of validity for this certificate.
    pub witness: Witness,
}

/// Proof of validity for a certificate.
///
/// A witness provides cryptographic evidence that a space handle is valid,
/// either through on-chain state proofs or off-chain delegation.
#[derive(Clone, Serialize, Deserialize)]
pub enum Witness {
    /// Witness for a top-level space registered on-chain.
    ///
    /// Contains merkle proofs against the on-chain spaces tree and optional
    /// ZK receipts proving commitment validity.
    Root {
        /// Merkle proof of the space's inclusion in the main on-chain spaces tree.
        inclusion: SpacesSubtree,
        /// Partial merkle paths from the pointers subtree containing
        /// commitment data and delegate information for the space.
        ptrs: Option<PtrsSubtree>,
        /// A ZK validity receipt recursively proving a commitment is valid
        /// up to the attested root hash.
        commitment: Option<Receipt>,
    },
    /// Witness for a delegated handle managed off-chain by an operator.
    ///
    /// Leaf witnesses prove that a handle was delegated from a parent space
    /// and track key rotation state.
    Leaf {
        /// The genesis script pubkey the handle was initialized with.
        /// This key may have been rotated on-chain since creation.
        ///
        /// **Warning**: Do not use directly for signature verification.
        genesis_spk: ScriptBuf,
        /// The type of leaf proof and its associated data.
        kind: LeafKind,
    },
}

/// The type of proof for a delegated leaf handle.
#[derive(Clone, Serialize, Deserialize)]
pub enum LeafKind {
    /// A finalized handle with full inclusion proofs.
    ///
    /// The handle has been committed to the operator's tree and can be
    /// verified against it.
    Final {
        /// Merkle proof of the handle's inclusion in the off-chain tree
        /// managed by the operator.
        inclusion: HandleSubtree,
        /// Merkle proof for existence or non-existence of a key rotation
        /// for this handle. Used to determine the current valid signing key.
        key_rotation: PtrsSubtree,
    },
    /// A temporary handle not yet committed to the operator's tree.
    ///
    /// Temporary handles are authorized by parent signature and may have
    /// an exclusion proof showing they haven't been revoked.
    Temporary {
        /// Optional exclusion proof showing this handle is not in the
        /// operator's revocation tree (required if parent has at least one commitment).
        exclusion: Option<HandleSubtree>,
        /// A schnorr signature from the parent authorizing this handle.
        signature: Signature,
    },
}

/// A 64-byte Schnorr signature.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct Signature(pub [u8; 64]);

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8> as Deserialize>::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature(arr))
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct SpacesSubtree(pub SubTree<Sha256Hasher>);
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct PtrsSubtree(pub SubTree<Sha256Hasher>);
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct HandleSubtree(pub SubTree<Sha256Hasher>);

pub enum SpacesValue {
    UTXO(SpaceOut),
    Space(SLabel),
    Unknown(Vec<u8>),
}

pub enum PtrsValue {
    UTXO(PtrOut),
    Space(SLabel),
    CommitmentTip(Hash),
    Commitment(Commitment),
    Unknown(Vec<u8>),
}


impl HandleSubtree {
    pub fn compute_root(&self) -> Result<Hash, SubtreeError> {
        Ok(self.0.compute_root()?)
    }

    pub fn contains_subspace(&self, label: &Label, genesis_spk: &ScriptBuf) -> Result<bool, SubtreeError> {
        let key = Sha256Hasher::hash(label.as_slabel().as_ref());
        let spkh = Sha256Hasher::hash(genesis_spk.as_bytes());

        if !self.0.contains(&key)? {
            return Ok(false);
        }
        Ok(self.0.iter().any(|(k, v)| *k == key && *v == spkh))
    }
}

struct KeyHash;

impl KeyHasher for KeyHash {
    fn hash(data: &[u8]) -> spaces_protocol::hasher::Hash {
        Sha256Hasher::hash(data)
    }
}

impl SpacesSubtree {
    pub fn iter(&self) -> SpacesIter<'_> {
        SpacesIter {
            inner: self.0.iter(),
        }
    }

    pub fn compute_root(&self) -> Result<Hash, SubtreeError> {
        Ok(self.0.compute_root()?)
    }

    /// Retrieves a UTXO leaf within the subtree specified the outpoint hash
    pub fn get_utxo(&self, utxo_key: &Hash) -> Option<SpaceOut> {
        let (_, value) = self.0.iter().find(|(k, _)| *k == utxo_key)?;
        let utxo: SpaceOut = borsh::from_slice(value).ok()?;
        Some(utxo)
    }

    /// Retrieves a UTXO leaf containing the specified space
    pub fn find_space(&self, space: &SLabel) -> Option<SpaceOut> {
        for (_, v) in self.iter() {
            match v {
                SpacesValue::UTXO(utxo) => {
                    if utxo
                        .space
                        .as_ref()
                        .is_some_and(|s| s.name.as_ref() == space.as_ref())
                    {
                        return Some(utxo);
                    }
                }
                _ => continue,
            }
        }
        None
    }
}

impl PtrsSubtree {
    pub fn iter(&self) -> PtrsIter<'_> {
        PtrsIter {
            inner: self.0.iter(),
        }
    }

    pub fn compute_root(&self) -> Result<Hash, SubtreeError> {
        Ok(self.0.compute_root()?)
    }

    pub fn has_commitments(&self, space: &SLabel) -> Result<bool, SubtreeError> {
        let key: Hash = RegistryKey::from_slabel::<KeyHash>(space).into();
        Ok(self.0.contains(&key)?)
    }

    /// Finds a PtrOut by its genesis SPK.
    ///
    /// Returns:
    /// - `Ok(Some(ptrout))` if found
    /// - `Ok(None)` if provably not in tree
    /// - `Err` if proof is malformed or incomplete
    pub fn find_sptr(&self, genesis_spk: &ScriptBuf) -> Result<Option<PtrOut>, SubtreeError> {
        let sptr = Sptr::from_spk::<KeyHash>(genesis_spk.clone());

        // Search for UTXO containing this sptr. We iterate rather than doing a direct
        // key lookup to avoid requiring an additional sptr->outpoint leaf in the proof.
        for (_, value) in self.iter() {
            if let PtrsValue::UTXO(ptrout) = value {
                if ptrout.sptr.as_ref().is_some_and(|ptr| ptr.id == sptr) {
                    return Ok(Some(ptrout));
                }
            }
        }

        // Not found in UTXOs - verify the sptr provably doesn't exist.
        // If contains() returns true, the proof is incomplete (has sptr key but missing UTXO).
        if self.0.contains(&sptr.to_bytes())? {
            return Err(SubtreeError::IncompleteProof {
                reason: "sptr key present but UTXO leaf missing".to_string(),
            });
        }

        Ok(None)
    }

    pub fn find_commitment(&self, space: &SLabel, commitment_root: Hash) -> Result<Option<Commitment>, SubtreeError> {
        let ck = CommitmentKey::new::<KeyHash>(space, commitment_root);
        let key: Hash = ck.into();

        // We use contains to error if the key doesn't provably exist/or doesn't exist.
        if !self.0.contains(&key)? {
            return Ok(None);
        }
        let (_, data) = self.0.iter().find(|(k, _)| **k == key)
            .expect("commitment must be found after checking with contains");

        let v: Commitment = borsh::from_slice(data)
            .map_err(|e| SubtreeError::DecodeFailed { reason: e.to_string() })?;
        Ok(Some(v))
    }

    /// Whether the subtree provably contains an sptr
    pub fn contains_sptr(&self, sptr: &Sptr) -> Result<bool, SubtreeError> {
        Ok(self.0.contains(&sptr.to_bytes())?)
    }
}

pub struct SpacesIter<'a> {
    inner: SubtreeIter<'a>,
}

pub struct PtrsIter<'a> {
    inner: SubtreeIter<'a>,
}

impl Iterator for PtrsIter<'_> {
    type Item = (Hash, PtrsValue);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| {
            // PTR proof: Try to decode value as different PTR types

            // Try PtrOutpointKey → PtrOut
            if let Ok(ptrout) = borsh::from_slice::<PtrOut>(v.as_slice()) {
                return (*k, PtrsValue::UTXO(ptrout));
            }

            // Try RegistryKey → Hash (root)
            if v.len() == 32 {
                if let Ok(root) = borsh::from_slice::<Hash>(v.as_slice()) {
                    return (*k, PtrsValue::CommitmentTip(root));
                }
            }

            (*k, PtrsValue::Unknown(v.clone()))
        })
    }
}

impl Iterator for SpacesIter<'_> {
    type Item = (Hash, SpacesValue);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| {
            // Spaces proof: OutpointKey → SpaceOut, SpaceKey → OutPoint
            if OutpointKey::is_valid(k) {
                let result = borsh::from_slice::<SpaceOut>(v.as_slice())
                    .ok()
                    .map(|raw| SpacesValue::UTXO(raw));
                return (*k, result.unwrap_or(SpacesValue::Unknown(v.clone())));
            }
            (*k, SpacesValue::Unknown(v.clone()))
        })
    }
}


// Serde implementations for subtree types (uses SubTreeEncoder for wire format)

impl Serialize for SpacesSubtree {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_subtree(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for SpacesSubtree {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(SpacesSubtree(deserialize_subtree(deserializer)?))
    }
}

impl Serialize for PtrsSubtree {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_subtree(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PtrsSubtree {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(PtrsSubtree(deserialize_subtree(deserializer)?))
    }
}

impl Serialize for HandleSubtree {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_subtree(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for HandleSubtree {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(HandleSubtree(deserialize_subtree(deserializer)?))
    }
}

fn serialize_subtree<S: Serializer>(subtree: &SubTree<Sha256Hasher>, serializer: S) -> Result<S::Ok, S::Error> {
    use serde::ser::Error;
    let mut buf = vec![0u8; SUBTREE_ENCODE_BUFFER_SIZE];
    let bytes_written = subtree
        .write_to_slice(&mut buf)
        .map_err(|e| S::Error::custom(format!("SubTreeEncoder error: {}", e)))?;
    buf.truncate(bytes_written);

    if serializer.is_human_readable() {
        let encoded = BASE64.encode(&buf);
        serializer.serialize_str(&encoded)
    } else {
        serializer.serialize_bytes(&buf)
    }
}

fn deserialize_subtree<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SubTree<Sha256Hasher>, D::Error> {
    use serde::de::Error;

    let buf = if deserializer.is_human_readable() {
        let encoded = <String as Deserialize>::deserialize(deserializer)?;
        BASE64.decode(&encoded)
            .map_err(|e| D::Error::custom(format!("base64 decode error: {}", e)))?
    } else {
        <Vec<u8> as Deserialize>::deserialize(deserializer)?
    };

    SubTree::from_slice(&buf)
        .map_err(|e| D::Error::custom(format!("SubTreeEncoder error: {}", e)))
}

// Manual Borsh implementations for Certificate, Witness, and LeafKind
// (ScriptBuf doesn't implement Borsh, so we serialize it as bytes)

impl BorshSerialize for Certificate {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.subject, writer)?;
        BorshSerialize::serialize(&self.witness, writer)
    }
}

impl BorshDeserialize for Certificate {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let subject = SName::deserialize_reader(reader)?;
        let witness = Witness::deserialize_reader(reader)?;
        Ok(Certificate { subject, witness })
    }
}

impl BorshSerialize for Witness {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            Witness::Root { inclusion, ptrs, commitment } => {
                BorshSerialize::serialize(&0u8, writer)?;
                BorshSerialize::serialize(inclusion, writer)?;
                BorshSerialize::serialize(ptrs, writer)?;
                BorshSerialize::serialize(commitment, writer)
            }
            Witness::Leaf { genesis_spk, kind } => {
                BorshSerialize::serialize(&1u8, writer)?;
                BorshSerialize::serialize(&genesis_spk.as_bytes().to_vec(), writer)?;
                BorshSerialize::serialize(kind, writer)
            }
        }
    }
}

impl BorshDeserialize for Witness {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let variant = u8::deserialize_reader(reader)?;
        match variant {
            0 => {
                let inclusion = SpacesSubtree::deserialize_reader(reader)?;
                let ptrs = Option::<PtrsSubtree>::deserialize_reader(reader)?;
                let commitment = Option::<Receipt>::deserialize_reader(reader)?;
                Ok(Witness::Root { inclusion, ptrs, commitment })
            }
            1 => {
                let spk_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
                let genesis_spk = ScriptBuf::from_bytes(spk_bytes);
                let kind = LeafKind::deserialize_reader(reader)?;
                Ok(Witness::Leaf { genesis_spk, kind })
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid Witness variant: {}", variant),
            )),
        }
    }
}

impl BorshSerialize for LeafKind {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            LeafKind::Final { inclusion, key_rotation } => {
                BorshSerialize::serialize(&0u8, writer)?;
                BorshSerialize::serialize(inclusion, writer)?;
                BorshSerialize::serialize(key_rotation, writer)
            }
            LeafKind::Temporary { exclusion, signature } => {
                BorshSerialize::serialize(&1u8, writer)?;
                BorshSerialize::serialize(exclusion, writer)?;
                BorshSerialize::serialize(signature, writer)
            }
        }
    }
}

impl BorshDeserialize for LeafKind {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let variant = u8::deserialize_reader(reader)?;
        match variant {
            0 => {
                let inclusion = HandleSubtree::deserialize_reader(reader)?;
                let key_rotation = PtrsSubtree::deserialize_reader(reader)?;
                Ok(LeafKind::Final { inclusion, key_rotation })
            }
            1 => {
                let exclusion = Option::<HandleSubtree>::deserialize_reader(reader)?;
                let signature = Signature::deserialize_reader(reader)?;
                Ok(LeafKind::Temporary { exclusion, signature })
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid LeafKind variant: {}", variant),
            )),
        }
    }
}


#[derive(Debug, Clone)]
pub enum SubtreeError {
    /// Proof is malformed, cannot compute root or verify inclusion
    MalformedProof { reason: String },
    /// Key is not provably included or excluded in the subtree
    KeyNotProvable { key: Hash },
    /// Failed to decode value from subtree
    DecodeFailed { reason: String },
    /// Proof is missing required data
    IncompleteProof { reason: String },
}

impl fmt::Display for SubtreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedProof { reason } => write!(f, "malformed proof: {}", reason),
            Self::KeyNotProvable { key } => {
                write!(f, "key {} not provable in subtree", hex::encode(key))
            }
            Self::DecodeFailed { reason } => write!(f, "decode failed: {}", reason),
            Self::IncompleteProof { reason } => write!(f, "incomplete proof: {}", reason),
        }
    }
}

impl std::error::Error for SubtreeError {}

impl From<spacedb::Error> for SubtreeError {
    fn from(e: spacedb::Error) -> Self {
        SubtreeError::MalformedProof {
            reason: e.to_string(),
        }
    }
}