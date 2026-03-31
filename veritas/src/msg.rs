use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};
use spaces_protocol::bitcoin::{ScriptBuf, secp256k1};
use spaces_protocol::constants::ChainAnchor;
use spaces_protocol::slabel::SLabel;
use std::collections::HashMap;
use std::io::{Read, Write};

use crate::{MessageError, Zone};
use crate::cert::{Certificate, HandleSubtree, NumsSubtree, Signature, SpacesSubtree, Witness};
use spaces_protocol::sname::{Subname, NameLike, SName};

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
        if let Some(existing) = self.zones.iter_mut().find(|z| z.canonical == zone.canonical) {
            *existing = zone;
        } else {
            self.zones.push(zone);
        }
    }

    /// Check if a handle is requested (empty requests = want all).
    pub fn wants(&self, handle: &SName) -> bool {
        self.requests.is_empty() || self.requests.iter().any(|h| h == handle)
    }

    /// Get a zone by canonical handle.
    pub fn get_zone(&self, handle: &SName) -> Option<&Zone> {
        self.zones.iter().find(|z| &z.canonical == handle)
    }

    /// Get the parent (root) zone for a space.
    ///
    /// For `alice@bitcoin`, this finds the `@bitcoin` zone.
    pub fn get_parent_zone(&self, space: &SLabel) -> Option<&Zone> {
        self.zones
            .iter()
            .find(|z| z.canonical.is_single_label() && z.canonical.space().as_ref() == Some(space))
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

    pub fn set_delegate_records(&mut self, handle: &SName, data: sip7::RecordSet) {
        self.set_records_inner(handle, data, true)
    }

    pub fn set_records(&mut self, handle: &SName, data: sip7::RecordSet) {
        self.set_records_inner(handle, data, false)
    }

    fn set_records_inner(&mut self, handle: &SName, data: sip7::RecordSet, delegate: bool) {
        let (space, subspace) = match handle.label_count() {
            1 => (handle.space().unwrap(), None),
            2 => (handle.space().unwrap(), Some(handle.subspace().unwrap())),
            _ => return,
        };

        let Some(bundle) = self.spaces
            .iter_mut()
            .find(|b| b.subject == space) else {
            return;
        };

        match subspace {
            None => match delegate {
                true => bundle.delegate_records = Some(data),
                false => bundle.records = Some(data),
            }
            Some(name) => {
                if let Some(handle) = bundle
                    .epochs
                    .iter_mut()
                    .flat_map(|e| e.handles.iter_mut())
                    .find(|h| h.name == name)
                {
                    handle.records = Some(data);
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
                    subject: label,
                    receipt: match root.witness {
                        Witness::Root { receipt } => receipt,
                        _ => continue,
                    },
                    epochs: vec![],
                    records: None,
                    delegate_records: None,
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
                        records: None,
                        signature,
                    });
                }
                None => bundle.epochs.push(Epoch {
                    tree: handles,
                    handles: vec![
                        Handle {
                            name: leaf.subject.subspace().unwrap(),
                            genesis_spk,
                            records: None,
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
    /// Proof from the nums tree (nums, delegation, commitments, key rotation).
    pub nums: NumsSubtree,
}

/// Data for a single space, including its tip receipt and handle epochs.
#[derive(Clone)]
pub struct Bundle {
    /// The subject this bundle is for (e.g., "@bitcoin", "#222-2-2").
    pub subject: SLabel,
    /// ZK receipt proving the tip epoch. `None` if the tip is finalized
    /// and the verifier's cache covers it, or for first-commitment spaces.
    /// When present, the journal decodes to the tip's final_root.
    pub receipt: Option<Receipt>,
    /// Signed records from the space owner.
    pub records: Option<sip7::RecordSet>,
    /// Signed records from the delegate.
    pub delegate_records: Option<sip7::RecordSet>,
    /// Handle epochs for this space. Each epoch corresponds to a committed
    /// state root. The tip epoch (if handles are being proven against it)
    /// should have `tree.compute_root()` matching the receipt's final_root
    /// or the on-chain tip from the chain proof.
    pub epochs: Vec<Epoch>,
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
    pub name: Subname,
    /// The genesis script pubkey the handle was initialized with.
    pub genesis_spk: ScriptBuf,
    /// Signed records from the handle owner (RecordSet with embedded Sig record).
    pub records: Option<sip7::RecordSet>,
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

/// Verify the Sig record in a RecordSet against a script pubkey.
///
/// 1. Finds the Sig record
/// 2. Checks signer matches expected_signer
/// 3. Re-packs with empty sig to get signing bytes
/// 4. Verifies schnorr signature against script_pubkey
pub fn verify_records(
    records: &sip7::RecordSet,
    script_pubkey: &ScriptBuf,
    expected_signer: &SName,
) -> Result<(), crate::SignatureError> {
    use secp256k1::XOnlyPublicKey;

    let all_records = records.unpack()
        .map_err(|_| crate::SignatureError::InvalidSignature)?;

    let sig_record = all_records.iter()
        .find_map(|r| match r {
            sip7::Record::Sig { signer, rev, sig } => Some((signer, rev, sig)),
            _ => None,
        })
        .ok_or(crate::SignatureError::InvalidSignature)?;

    let (signer, _rev, sig_bytes) = sig_record;

    if signer != expected_signer {
        return Err(crate::SignatureError::VerificationFailed);
    }

    // Re-pack with empty sig to get signing bytes
    let signing_records: Vec<sip7::Record> = all_records.iter().map(|r| match r {
        sip7::Record::Sig { signer, rev, .. } => {
            sip7::Record::sig(signer.clone(), rev.clone(), vec![])
        }
        other => other.clone(),
    }).collect();

    let signing_set = sip7::RecordSet::pack(signing_records)
        .map_err(|_| crate::SignatureError::InvalidSignature)?;

    let script_bytes = script_pubkey.as_bytes();
    if script_bytes.len() != secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE + 2 {
        return Err(crate::SignatureError::InvalidPublicKey);
    }
    let pubkey = XOnlyPublicKey::from_slice(&script_bytes[2..])
        .map_err(|_| crate::SignatureError::InvalidPublicKey)?;
    let msg = crate::hash_signable_message(signing_set.as_slice());
    let sig = secp256k1::schnorr::Signature::from_slice(sig_bytes)
        .map_err(|_| crate::SignatureError::InvalidSignature)?;
    secp256k1::Secp256k1::verification_only()
        .verify_schnorr(&sig, &msg, &pubkey)
        .map_err(|_| crate::SignatureError::VerificationFailed)
}

/// Extract the Sig record from a RecordSet, if present.
///
/// Returns `(signer, rev, sig_bytes)`.
pub fn find_sig(records: &sip7::RecordSet) -> Option<(SName, SName, Vec<u8>)> {
    let unpacked = records.unpack().ok()?;
    unpacked.into_iter().find_map(|r| match r {
        sip7::Record::Sig { signer, rev, sig } => Some((signer, rev, sig)),
        _ => None,
    })
}

/// Append a Sig record with empty signature to a RecordSet.
///
/// If a Sig record already exists, the RecordSet is returned unchanged.
///
/// `signer` is the canonical/flattened name (e.g. `alice#800-12-12`).
/// `rev` is the original human-readable name (e.g. `alice@bitcoin`).
/// Returns a new RecordSet whose wire bytes are the signing payload.
pub fn pack_sig(signer: &SName, rev: &SName, records: &sip7::RecordSet) -> Result<sip7::RecordSet, sip7::Error> {
    if find_sig(records).is_some() {
        return Ok(records.clone());
    }
    let mut unpacked = records.unpack()?;
    unpacked.push(sip7::Record::sig(signer.clone(), rev.clone(), vec![]));
    sip7::RecordSet::pack(unpacked)
}

/// An unsigned record set pending signature.
pub struct UnsignedRecord {
    /// The original handle name (before flattening, e.g. `alice@bitcoin`).
    pub handle: SName,
    /// The canonical/flattened signer name (e.g. `alice#800-12-12`).
    /// Pass this to `Message::set_signature()`.
    pub signer: SName,
    /// The 32-byte signing hash (Spaces signed-message prefix + SHA256).
    pub signing_id: [u8; 32],
}

impl Message {
    /// Set the signature on a record set identified by its signer name.
    ///
    /// Finds the RecordSet with a Sig record whose signer matches the handle,
    /// then re-packs with the provided signature bytes.
    pub fn set_signature(&mut self, handle: &SName, signature: Vec<u8>) {
        for bundle in &mut self.spaces {
            if try_inject_sig(&mut bundle.records, handle, &signature) { return; }
            if try_inject_sig(&mut bundle.delegate_records, handle, &signature) { return; }

            for epoch in &mut bundle.epochs {
                for h in &mut epoch.handles {
                    if try_inject_sig(&mut h.records, handle, &signature) { return; }
                }
            }
        }
    }
}

/// Extract the signer from an empty Sig record, if present.
fn extract_empty_sig_signer(records: &sip7::RecordSet) -> Option<SName> {
    let unpacked = records.unpack().ok()?;
    unpacked.iter().find_map(|r| match r {
        sip7::Record::Sig { signer, sig, .. } if sig.is_empty() => Some(signer.clone()),
        _ => None,
    })
}

pub fn signing_id_for(records: &sip7::RecordSet) -> [u8; 32] {
    let msg = crate::hash_signable_message(records.as_slice());
    *msg.as_ref()
}

/// Try to inject a signature into a record set if its Sig signer matches the handle.
/// Returns true if the signature was injected.
fn try_inject_sig(records: &mut Option<sip7::RecordSet>, handle: &SName, signature: &[u8]) -> bool {
    let Some(rs) = records.as_ref() else { return false };
    let Some(signer) = extract_empty_sig_signer(rs) else { return false };
    if &signer != handle { return false; }

    let Ok(unpacked) = rs.unpack() else { return false };
    let updated: Vec<sip7::Record> = unpacked.into_iter().map(|r| match r {
        sip7::Record::Sig { signer, rev, sig } if sig.is_empty() => {
            sip7::Record::sig(signer, rev, signature.to_vec())
        }
        other => other,
    }).collect();

    if let Ok(new_rs) = sip7::RecordSet::pack(updated) {
        *records = Some(new_rs);
        true
    } else {
        false
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
        BorshSerialize::serialize(&self.nums, writer)
    }
}

impl BorshDeserialize for ChainProof {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let anchor = ChainAnchor::deserialize_reader(reader)?;
        let spaces = SpacesSubtree::deserialize_reader(reader)?;
        let nums = NumsSubtree::deserialize_reader(reader)?;
        Ok(ChainProof { anchor, spaces, nums })
    }
}

impl BorshSerialize for Bundle {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.subject, writer)?;
        BorshSerialize::serialize(&self.receipt, writer)?;
        BorshSerialize::serialize(&self.epochs, writer)?;
        let records_bytes: Option<Vec<u8>> = self.records.as_ref().map(|d| d.as_slice().to_vec());
        BorshSerialize::serialize(&records_bytes, writer)?;
        let delegate_bytes: Option<Vec<u8>> = self.delegate_records.as_ref().map(|d| d.as_slice().to_vec());
        BorshSerialize::serialize(&delegate_bytes, writer)
    }
}

impl BorshDeserialize for Bundle {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let space = SLabel::deserialize_reader(reader)?;
        let receipt = Option::<Receipt>::deserialize_reader(reader)?;
        let epochs = Vec::<Epoch>::deserialize_reader(reader)?;
        let records_bytes: Option<Vec<u8>> = Option::<Vec<u8>>::deserialize_reader(reader)?;
        let delegate_bytes: Option<Vec<u8>> = Option::<Vec<u8>>::deserialize_reader(reader)?;
        Ok(Bundle {
            subject: space,
            receipt,
            epochs,
            records: records_bytes.map(sip7::RecordSet::new),
            delegate_records: delegate_bytes.map(sip7::RecordSet::new),
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
        let records_bytes: Option<Vec<u8>> = self.records.as_ref().map(|d| d.as_slice().to_vec());
        BorshSerialize::serialize(&records_bytes, writer)?;
        BorshSerialize::serialize(&self.signature, writer)
    }
}

impl BorshDeserialize for Handle {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let name = Subname::deserialize_reader(reader)?;
        let spk_bytes: Vec<u8> = Vec::deserialize_reader(reader)?;
        let genesis_spk = ScriptBuf::from_bytes(spk_bytes);
        let records_bytes: Option<Vec<u8>> = Option::<Vec<u8>>::deserialize_reader(reader)?;
        let signature = Option::<Signature>::deserialize_reader(reader)?;
        Ok(Handle {
            name,
            genesis_spk,
            records: records_bytes.map(sip7::RecordSet::new),
            signature,
        })
    }
}