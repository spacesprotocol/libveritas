use std::fmt;
use std::io::{Read, Write};
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spacedb::subtree::{SubTree, SubtreeIter};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::Receipt;
use spaces_protocol::bitcoin::ScriptBuf;
use spaces_protocol::hasher::{KeyHasher, OutpointKey};
use spaces_protocol::slabel::SLabel;
use spaces_protocol::SpaceOut;
use spaces_ptr::{ChainProofRequest, Commitment, CommitmentKey, PtrKeyKind, PtrOut, RegistryKey};
use spaces_ptr::sptr::Sptr;
use crate::sname::{Label, SName};

/// Current certificate version.
pub const CERTIFICATE_VERSION: u8 = 2;

/// A slim offline backup certificate for space handle ownership.
///
/// Certificate contains only data that cannot be recovered from a spaced client:
/// - The ZK receipt (for root certs, produced by the operator)
/// - Handle subtree proofs (from the operator's off-chain tree)
/// - Signatures and identity information
///
/// On-chain proofs (spaces tree, ptrs tree) are always recoverable from any
/// spaced client and are not stored in the certificate. They are assembled
/// into a [`CertificateBundle`](crate::bundle::CertificateBundle) for verification.
///
/// # Certificate Types
///
/// - **Root certificates** (`Witness::Root`) — for top-level spaces (e.g., `@bitcoin`)
/// - **Leaf certificates** (`Witness::Leaf`) — for handles under a space (e.g., `alice@bitcoin`)
///   - Final: handle is committed to the operator's tree (inclusion proof)
///   - Temporary: handle is authorized by parent signature (exclusion proof)
#[derive(Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Certificate format version for future compatibility.
    pub version: u8,
    /// The space handle this certificate attests to.
    pub subject: SName,
    /// The witness proving this certificate's validity.
    pub witness: Witness,
}

/// Witness for a certificate, containing only non-recoverable proof data.
#[derive(Clone, Serialize, Deserialize)]
pub enum Witness {
    /// Root certificate for a top-level space.
    Root {
        /// ZK receipt proving commitment validity. May prove a NEWER commitment
        /// than the certificate's `commitment_root` (recursive coverage).
        receipt: Option<Receipt>,
    },
    /// Leaf certificate for a delegated handle.
    Leaf {
        /// The genesis script pubkey the handle was initialized with.
        /// This key may have been rotated on-chain since creation.
        genesis_spk: ScriptBuf,
        /// Handle subtree proof:
        /// - For final certs (signature is None): inclusion proof
        /// - For temporary certs (signature is Some): exclusion proof
        handles: HandleSubtree,
        /// Present for temporary certificates — a schnorr signature from
        /// the parent delegate/owner authorizing this handle.
        /// None for final certificates (committed to operator's tree).
        signature: Option<Signature>,
    },
}

impl Certificate {
    /// Creates a new certificate with the current version.
    pub fn new(subject: SName, witness: Witness) -> Self {
        Self {
            version: CERTIFICATE_VERSION,
            subject,
            witness,
        }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, std::io::Error> {
        borsh::from_slice(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("certificate serialization should not fail")
    }

    /// Returns true if this is a leaf certificate.
    pub fn is_leaf(&self) -> bool {
        matches!(self.witness, Witness::Leaf { .. })
    }

    /// Returns true if this is a temporary leaf certificate.
    /// Root certificates are never temporary.
    pub fn is_temporary(&self) -> bool {
        matches!(
            self.witness,
            Witness::Leaf { signature: Some(_), .. }
        )
    }

    /// Returns true if this is a final certificate.
    /// Root certificates are always final. Leaf certificates are final
    /// when committed (no signature).
    pub fn is_final(&self) -> bool {
        match &self.witness {
            Witness::Root { .. } => true,
            Witness::Leaf { signature, .. } => signature.is_none(),
        }
    }

    /// Returns the genesis script pubkey if this is a leaf certificate.
    pub fn genesis_spk(&self) -> Option<&ScriptBuf> {
        match &self.witness {
            Witness::Leaf { genesis_spk, .. } => Some(genesis_spk),
            _ => None,
        }
    }

    /// Returns the Sptr derived from the genesis script pubkey if this is a leaf certificate.
    pub fn sptr(&self) -> Option<Sptr> {
        self.genesis_spk().map(|spk| Sptr::from_spk::<KeyHash>(spk.clone()))
    }
}

pub trait ChainProofRequestUtils {
    fn add(&mut self, cert: &Certificate);
    fn from_certificates<'a>(certs: impl Iterator<Item = &'a Certificate>) -> Self;

    fn add_subtree(&mut self, space: &SLabel, handles: &HandleSubtree);
}

impl ChainProofRequestUtils for ChainProofRequest {

    /// Add keys needed to verify a certificate.
    fn add(&mut self, cert: &Certificate) {
        let Some(space) = cert.subject.space() else {
            return;
        };

        // Space proof
        if !self.spaces.iter().any(|s| s == &space) {
            self.spaces.push(space.clone());
        }

        // Registry key for commitment tip
        let registry_key = RegistryKey::from_slabel::<KeyHash>(&space);
        if !self.ptrs_keys.iter().any(|k| matches!(k, PtrKeyKind::Registry(r) if *r == registry_key)) {
            self.ptrs_keys.push(PtrKeyKind::Registry(registry_key));
        }

        match &cert.witness {
            Witness::Root { .. } => {}
            Witness::Leaf { genesis_spk, handles, .. } => {
                // Commitment key for epoch root (only if tree is non-empty)
                if !handles.0.is_empty() {
                    if let Ok(root) = handles.compute_root() {
                        let ck = CommitmentKey::new::<KeyHash>(&space, root);
                        if !self.ptrs_keys.iter().any(|k| matches!(k, PtrKeyKind::Commitment(c) if *c == ck)) {
                            self.ptrs_keys.push(PtrKeyKind::Commitment(ck));
                        }
                    }
                }

                // Sptr key for key rotation lookup
                let sptr = Sptr::from_spk::<KeyHash>(genesis_spk.clone());
                if !self.ptrs_keys.iter().any(|k| matches!(k, PtrKeyKind::Sptr(s) if *s == sptr)) {
                    self.ptrs_keys.push(PtrKeyKind::Sptr(sptr));
                }
            }
        }
    }

    /// Build from an iterator of certificates.
     fn from_certificates<'a>(certs: impl Iterator<Item = &'a Certificate>) -> Self {
        let mut req = Self {
            spaces: vec![],
            ptrs_keys: vec![],
        };
        for cert in certs {
            req.add(cert);
        }
        req
    }

    /// Add keys from a handle subtree for a space.
    ///
    /// Iterates the subtree to extract genesis_spk values and compute sptr keys.
    fn add_subtree(&mut self, space: &SLabel, handles: &HandleSubtree) {
        // Space proof
        if !self.spaces.iter().any(|s| s == space) {
            self.spaces.push(space.clone());
        }

        // Registry key for commitment tip
        let registry_key = RegistryKey::from_slabel::<KeyHash>(space);
        if !self.ptrs_keys.iter().any(|k| matches!(k, PtrKeyKind::Registry(r) if *r == registry_key)) {
            self.ptrs_keys.push(PtrKeyKind::Registry(registry_key));
        }

        if handles.0.is_empty() {
            return;
        }

        // Commitment key for subtree root
        if let Ok(root) = handles.compute_root() {
            let ck = CommitmentKey::new::<KeyHash>(space, root);
            if !self.ptrs_keys.iter().any(|k| matches!(k, PtrKeyKind::Commitment(c) if *c == ck)) {
                self.ptrs_keys.push(PtrKeyKind::Commitment(ck));
            }
        }

        // Sptr keys from all handles in subtree
        for (_, genesis_spk_bytes) in handles.0.iter() {
            let genesis_spk = ScriptBuf::from_bytes(genesis_spk_bytes.to_vec());
            let sptr = Sptr::from_spk::<KeyHash>(genesis_spk);
            if !self.ptrs_keys.iter().any(|k| matches!(k, PtrKeyKind::Sptr(s) if *s == sptr)) {
                self.ptrs_keys.push(PtrKeyKind::Sptr(sptr));
            }
        }
    }
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
    CommitmentTip(Hash),
    Commitment(Commitment),
    Unknown(Vec<u8>),
}


impl HandleSubtree {
    pub fn compute_root(&self) -> Result<Hash, SubtreeError> {
        Ok(self.0.compute_root()?)
    }

    pub fn inner(&mut self) -> &mut SubTree<Sha256Hasher> {
        &mut self.0
    }

    pub fn contains_subspace(&self, label: &Label, genesis_spk: &ScriptBuf) -> Result<bool, SubtreeError> {
        let key = Sha256Hasher::hash(label.as_slabel().as_ref());

        if !self.0.contains(&key)? {
            return Ok(false);
        }

        let genesis_spk_matches = self.0.iter()
            .any(|(k, v)| *k == key && *v == genesis_spk.as_bytes());
        Ok(genesis_spk_matches)
    }
}

pub struct KeyHash;

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

    pub fn inner(&mut self) -> &mut SubTree<Sha256Hasher> {
        &mut self.0
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

    pub fn inner(&mut self) -> &mut SubTree<Sha256Hasher> {
        &mut self.0
    }

    pub fn compute_root(&self) -> Result<Hash, SubtreeError> {
        Ok(self.0.compute_root()?)
    }

    pub fn has_commitments(&self, space: &SLabel) -> Result<bool, SubtreeError> {
        let key: Hash = RegistryKey::from_slabel::<KeyHash>(space).into();
        Ok(self.0.contains(&key)?)
    }

    pub fn get_latest_commitment_root(&self, space: &SLabel) -> Result<Option<Hash>, SubtreeError> {
        let key: Hash = RegistryKey::from_slabel::<KeyHash>(space).into();

        // Find the commitment tip entry
        for (k, value) in self.iter() {
            if k == key {
                if let PtrsValue::CommitmentTip(tip_root) = value {
                    return Ok(Some(tip_root));
                }
            }
        }
        // Tip not found in proof - check if it provably doesn't exist
        if self.0.contains(&key)? {
            // Key exists but we didn't find it in iteration - incomplete proof
            Err(SubtreeError::IncompleteProof {
                reason: "commitment tip key present but value missing".to_string(),
            })
        } else {
            // No commitments exist for this space
            Ok(None)
        }
    }

    /// Checks if the given state_root is the latest commitment for the space.
    ///
    /// Returns:
    /// - `Ok(true)` if the commitment tip for this space matches state_root
    /// - `Ok(false)` if the commitment tip exists but doesn't match
    /// - `Err` if the tip cannot be proven
    pub fn is_latest_commitment(&self, space: &SLabel, state_root: Hash) -> Result<bool, SubtreeError> {
        let key: Hash = RegistryKey::from_slabel::<KeyHash>(space).into();

        // Find the commitment tip entry
        for (k, value) in self.iter() {
            if k == key {
                if let PtrsValue::CommitmentTip(tip_root) = value {
                    return Ok(tip_root == state_root);
                }
            }
        }

        // Tip not found in proof - check if it provably doesn't exist
        if self.0.contains(&key)? {
            // Key exists but we didn't find it in iteration - incomplete proof
            Err(SubtreeError::IncompleteProof {
                reason: "commitment tip key present but value missing".to_string(),
            })
        } else {
            // No commitments exist for this space
            Err(SubtreeError::KeyNotProvable { key })
        }
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

            // Try CommitmentKey → Commitment
            if let Ok(c) = borsh::from_slice::<Commitment>(v.as_slice()) {
                return (*k, PtrsValue::Commitment(c));
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
    let buf = subtree.to_vec()
        .map_err(|e| S::Error::custom(format!("SubTree encode error: {}", e)))?;

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

// Manual Borsh implementations for Certificate and CertificateWitness
// (ScriptBuf doesn't implement Borsh, so we serialize it as bytes)

impl BorshSerialize for Certificate {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.version, writer)?;
        BorshSerialize::serialize(&self.subject, writer)?;
        BorshSerialize::serialize(&self.witness, writer)
    }
}

impl BorshDeserialize for Certificate {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let version = u8::deserialize_reader(reader)?;
        let subject = SName::deserialize_reader(reader)?;
        let witness = Witness::deserialize_reader(reader)?;
        Ok(Certificate { version, subject, witness })
    }
}

impl BorshSerialize for Witness {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            Witness::Root { receipt } => {
                BorshSerialize::serialize(&0u8, writer)?;
                BorshSerialize::serialize(receipt, writer)
            }
            Witness::Leaf { genesis_spk, handles, signature } => {
                BorshSerialize::serialize(&1u8, writer)?;
                BorshSerialize::serialize(&genesis_spk.as_bytes().to_vec(), writer)?;
                BorshSerialize::serialize(handles, writer)?;
                BorshSerialize::serialize(signature, writer)
            }
        }
    }
}

impl BorshDeserialize for Witness {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let variant = u8::deserialize_reader(reader)?;
        match variant {
            0 => {
                let receipt = Option::<Receipt>::deserialize_reader(reader)?;
                Ok(Witness::Root { receipt })
            }
            1 => {
                let spk_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
                let genesis_spk = ScriptBuf::from_bytes(spk_bytes);
                let handles = HandleSubtree::deserialize_reader(reader)?;
                let signature = Option::<Signature>::deserialize_reader(reader)?;
                Ok(Witness::Leaf { genesis_spk, handles, signature })
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid CertificateWitness variant: {}", variant),
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