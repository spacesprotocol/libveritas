//! Proof-path inspection for visualization.
//!
//! Walks the merkle subtrees touched during message verification and emits a
//! JSON-serializable report (anchor + per-zone proof paths). Intended for
//! offline visualizers. It checks record-set signatures (cheap schnorr) so it
//! can flag sets omitted from the verified message, but does not perform ZK
//! receipt verification.

use crate::cert::{HandleSubtree, KeyHash, NumsSubtree, NumsValue, SpacesSubtree, SpacesValue};
use crate::msg::{ChainProof, Message};
use crate::{Veritas, compute_root_id, deserialize_hash, serialize_hash};
use serde::{Deserialize, Serialize};
use spacedb::path::{BitLength, Direction, Path, PathUtils};
use spacedb::subtree::{SubTreeNode, ValueOrHash};
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spaces_nums::num_id::NumId;
use spaces_nums::snumeric::SNumeric;
use spaces_nums::{Commitment, CommitmentKey, CommitmentTipKey};
use spaces_protocol::bitcoin::hashes::Hash as _;
use spaces_protocol::sname::SName;
use std::fmt;

#[derive(Debug, Clone)]
pub enum InspectError {
    NoAnchorAtHeight(u32),
    AnchorOutOfRange { anchor: u32, oldest: u32, tip: u32 },
    SpaceNotFound(String),
    IncompleteProof(&'static str),
}

impl fmt::Display for InspectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAnchorAtHeight(h) => write!(f, "no anchor at height {h}"),
            Self::AnchorOutOfRange {
                anchor,
                oldest,
                tip,
            } => write!(f, "anchor {anchor} outside range [{oldest}, {tip}]"),
            Self::SpaceNotFound(s) => write!(f, "space not found in proof: {s}"),
            Self::IncompleteProof(why) => write!(f, "incomplete proof: {why}"),
        }
    }
}

impl std::error::Error for InspectError {}

#[derive(Serialize, Deserialize)]
pub struct InspectReport {
    pub anchor: AnchorInfo,
    pub zones: Vec<ZoneInspect>,
}

#[derive(Serialize, Deserialize)]
pub struct AnchorInfo {
    pub block_height: u32,
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub block_hash: Hash,
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub spaces_root: Hash,
    #[serde(
        serialize_with = "crate::serialize_option_hash",
        deserialize_with = "crate::deserialize_option_hash"
    )]
    pub nums_root: Option<Hash>,
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub anchor_hash: Hash,
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ZoneKind {
    Space,
    Numeric,
    Handle,
}

#[derive(Serialize, Deserialize)]
pub struct ZoneInspect {
    pub handle: String,
    pub kind: ZoneKind,
    /// For handles, the parent space (e.g. "@bitcoin").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Finality state this zone resolves to (sovereign / pending / dependent).
    /// `None` when no commitment covers the zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sovereignty: Option<crate::SovereigntyState>,
    /// Decoded ZK receipt summary — present on a parent zone whose bundle
    /// carried a receipt. Not verified, just decoded for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ReceiptInfo>,
    /// Owner / delegate signed-record summaries (seq, signer, canonical name).
    #[serde(skip_serializing_if = "RecordsInfo::is_empty")]
    pub records: RecordsInfo,
    pub paths: Vec<ProofPath>,
}

/// Decoded (unverified) ZK receipt journal for a parent zone.
#[derive(Serialize, Deserialize, Clone)]
pub struct ReceiptInfo {
    /// Recursion kind: "fold" or "step".
    pub kind: String,
    /// The state root the proven transition starts from.
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub initial_root: Hash,
    /// The committed state root the transition ends at.
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub final_root: Hash,
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub rolling_hash: Hash,
    /// Whether the journal's policy IDs match this build's FOLD/STEP image IDs.
    pub policy_ok: bool,
}

/// Signed-record summaries attached to a zone.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct RecordsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<RecordSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegate: Option<RecordSummary>,
}

impl RecordsInfo {
    fn is_empty(&self) -> bool {
        self.owner.is_none() && self.delegate.is_none()
    }
}

/// The signing metadata from a record set's embedded Sig record.
#[derive(Serialize, Deserialize, Clone)]
pub struct RecordSummary {
    /// Monotonic sequence number (freshness).
    pub seq: u64,
    /// Sig record flags (e.g. SIG_PRIMARY_ZONE).
    pub flags: u8,
    /// Canonical name the signature commits to.
    pub canonical: String,
    /// Human-readable handle name the signature commits to.
    pub handle: String,
    /// Signature status against the resolved signer key. `Invalid` sets are
    /// omitted from the verified message — this is the only place their
    /// presence is surfaced.
    pub signature: SigStatus,
}

/// Verification status of a record set's embedded signature.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigStatus {
    /// Signature verifies against the resolved signer key.
    Valid,
    /// A Sig record is present but does not verify — these records are omitted
    /// from the verified message (e.g. signed by a rotated or foreign key).
    Invalid,
    /// The signer key could not be resolved offline, so the signature was not
    /// checked.
    Unchecked,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TreeKind {
    SpacesRoot,
    NumsRoot,
    HandlesRoot,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProofPurpose {
    /// SpaceOut for a named space in the spaces tree.
    SpaceUtxo,
    /// NumOut for a numeric space in the nums tree.
    NumericUtxo,
    /// Commitment tip key for a space (latest committed root).
    CommitmentTip,
    /// Commitment record (state_root → prev_root + rolling_hash).
    Commitment,
    /// NumOut keyed by the parent's own num_id — proves whether the parent
    /// has a registered delegate (the signing authority for temporary handles).
    DelegateLookup,
    /// NumOut keyed by a handle's genesis num_id — proves key rotation
    /// (the handle's current script pubkey may differ from genesis).
    KeyRotation,
    /// Handle inclusion in the operator's epoch handles tree.
    HandleInclusion,
    /// Handle exclusion (temporary cert) in the epoch handles tree.
    HandleExclusion,
}

/// How the walk for a queried key terminated.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// The key matched a leaf (inclusion).
    Included,
    /// The key is provably absent: the walk diverged or hit an empty slot.
    ProvablyExcluded,
    /// The proof is pruned where the walk needed to continue — cannot tell.
    Incomplete,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ProofPath {
    pub tree: TreeKind,
    pub purpose: ProofPurpose,
    /// The root hash this path verifies against.
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub root: Hash,
    /// The key being looked up (32-byte hash).
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub key: Hash,
    /// How the walk terminated (included / provably excluded / incomplete).
    pub resolution: Resolution,
    /// Where the next path's root should come from (visualizer hint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provides_root: Option<TreeKind>,
    /// For a commitment path: the decoded commitment's structure. Lets a
    /// visualizer show the epoch chain and whether ZK was required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<CommitmentMeta>,
    pub leaf: Option<LeafInfo>,
    pub steps: Vec<PathStep>,
}

/// Structural facts about a commitment, for the trust-path graph.
#[derive(Serialize, Deserialize, Clone)]
pub struct CommitmentMeta {
    /// Block height the commitment was made at.
    pub block_height: u32,
    /// The committed handles-tree root (also this epoch's handles root).
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub state_root: Hash,
    /// Previous committed root the transition builds on. `None` for the first
    /// (genesis) commitment.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::serialize_option_hash",
        deserialize_with = "crate::deserialize_option_hash"
    )]
    pub prev_root: Option<Hash>,
    /// A genesis (first) commitment proves its handles directly — no ZK
    /// receipt is required. Later epochs need a fold/step proof of the
    /// `prev_root → state_root` transition.
    pub genesis: bool,
    /// Whether the message's ZK receipt directly proves this exact commitment
    /// (its `final_root` equals `state_root`). A fold receipt at a newer epoch
    /// also covers this one recursively even when this is false.
    pub directly_proven: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LeafInfo {
    /// The leaf's actual key (may differ from the queried key for an exclusion proof).
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub key: Hash,
    /// Hash of the leaf value.
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub value_hash: Hash,
    /// Decoded type when recognizable: "SpaceOut" | "NumOut" | "Commitment"
    /// | "CommitmentTip" | "HandleOut" | "Unknown".
    pub value_kind: String,
    /// For a NumOut leaf: whether the num is spent (dormant, rebindable).
    /// Dormant nums still resolve, so this is informational.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spent: Option<bool>,
    /// Whether the queried key matched this leaf.
    pub matched: bool,
}

#[derive(Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    Left,
    Right,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PathStep {
    pub depth: u32,
    pub prefix_bit_len: u32,
    /// Compressed prefix bytes (MSB-first, length = ceil(prefix_bit_len/8)).
    #[serde(with = "hex_bytes")]
    pub prefix: Vec<u8>,
    pub direction: Dir,
    #[serde(
        serialize_with = "serialize_hash",
        deserialize_with = "deserialize_hash"
    )]
    pub sibling_hash: Hash,
}

/// Compute hash of any SubTreeNode (mirrors spacedb's private hash_node).
fn hash_node<H: NodeHasher>(node: &SubTreeNode) -> Result<Hash, InspectError> {
    match node {
        SubTreeNode::Leaf { key, value_or_hash } => {
            let v_hash = match value_or_hash {
                ValueOrHash::Value(v) => H::hash(v),
                ValueOrHash::Hash(h) => *h,
            };
            Ok(H::hash_leaf(&key.0, &v_hash))
        }
        SubTreeNode::Internal {
            prefix,
            left,
            right,
        } => {
            let l = hash_node::<H>(left)?;
            let r = hash_node::<H>(right)?;
            Ok(H::hash_internal(prefix.as_bytes(), &l, &r))
        }
        SubTreeNode::Hash(h) => Ok(*h),
        SubTreeNode::None => Err(InspectError::IncompleteProof("hash empty")),
    }
}

/// Walk the path from root to the leaf matching `key`, returning the steps,
/// the terminal leaf (if any), and how the walk resolved:
/// - `Included`: the key matched a leaf.
/// - `ProvablyExcluded`: the walk diverged or hit an empty slot — key absent.
/// - `Incomplete`: the proof is pruned where the walk needed to continue.
fn walk_path<H: NodeHasher>(
    root: &SubTreeNode,
    key: &Hash,
) -> Result<(Vec<PathStep>, Option<LeafInfo>, Resolution), InspectError> {
    let key_path = Path(key);
    let mut steps = Vec::new();
    let mut node = root;
    let mut depth: usize = 0;

    loop {
        match node {
            SubTreeNode::Leaf {
                key: leaf_key,
                value_or_hash,
            } => {
                let matched = leaf_key.0 == *key;
                let (value_hash, value_kind, spent) = match value_or_hash {
                    ValueOrHash::Value(v) => (
                        H::hash(v),
                        classify_value(v.as_slice()),
                        decode_spent(v.as_slice()),
                    ),
                    ValueOrHash::Hash(h) => (*h, "Unknown", None),
                };
                let resolution = if matched {
                    Resolution::Included
                } else {
                    // A different key sits where ours would be → provably absent.
                    Resolution::ProvablyExcluded
                };
                return Ok((
                    steps,
                    Some(LeafInfo {
                        key: leaf_key.0,
                        value_hash,
                        value_kind: value_kind.to_string(),
                        spent,
                        matched,
                    }),
                    resolution,
                ));
            }
            SubTreeNode::Internal {
                prefix,
                left,
                right,
            } => {
                // Diverging prefix: key cannot be in this subtree.
                if key_path.split_point(depth, *prefix).is_some() {
                    return Ok((steps, None, Resolution::ProvablyExcluded));
                }
                depth += prefix.bit_len();
                let dir = key_path.direction(depth);
                let (chosen, sibling, dir_enum) = match dir {
                    Direction::Left => (left.as_ref(), right.as_ref(), Dir::Left),
                    Direction::Right => (right.as_ref(), left.as_ref(), Dir::Right),
                };
                let prefix_bit_len = prefix.bit_len();
                let as_bytes = prefix.as_bytes();
                // as_bytes returns [len_byte, ...prefix_bytes...]
                let prefix_bytes = if as_bytes.len() > 1 {
                    as_bytes[1..].to_vec()
                } else {
                    Vec::new()
                };
                steps.push(PathStep {
                    depth: depth as u32 - prefix_bit_len as u32,
                    prefix_bit_len: prefix_bit_len as u32,
                    prefix: prefix_bytes,
                    direction: dir_enum,
                    sibling_hash: hash_node::<H>(sibling)?,
                });
                depth += 1;
                node = chosen;
            }
            SubTreeNode::Hash(_) => {
                // Proof pruned here — cannot tell inclusion from exclusion.
                return Ok((steps, None, Resolution::Incomplete));
            }
            SubTreeNode::None => {
                // Empty slot: the key provably has no leaf here.
                return Ok((steps, None, Resolution::ProvablyExcluded));
            }
        }
    }
}

/// If the leaf value decodes as a NumOut, return its `spent` (dormancy) flag.
fn decode_spent(bytes: &[u8]) -> Option<bool> {
    borsh::from_slice::<spaces_nums::NumOut>(bytes)
        .ok()
        .map(|n| n.spent)
}

/// Decode (without verifying) a ZK receipt journal into a display summary.
fn receipt_info(receipt: &risc0_zkvm::Receipt) -> Option<ReceiptInfo> {
    let zkc = receipt
        .journal
        .decode::<libveritas_zk::guest::Commitment>()
        .ok()?;
    let policy_ok = zkc.policy_fold == crate::constants::FOLD_ID
        && zkc.policy_step == crate::constants::STEP_ID;
    let kind = match zkc.kind {
        libveritas_zk::guest::CommitmentKind::Fold => "fold",
        libveritas_zk::guest::CommitmentKind::Step => "step",
    };
    Some(ReceiptInfo {
        kind: kind.to_string(),
        initial_root: zkc.initial_root,
        final_root: zkc.final_root,
        rolling_hash: zkc.rolling_hash,
        policy_ok,
    })
}

/// Summarize a record set's embedded Sig record (seq + signer identity) and
/// check its signature against `signer_spk` when a signer key can be resolved.
/// Mirrors the omit-on-invalid behavior of verification so the report can flag
/// sets that were dropped from the verified message.
fn record_summary(
    records: &sip7::RecordSet,
    signer_spk: Option<&spaces_protocol::bitcoin::ScriptBuf>,
    canonical: &SName,
) -> Option<RecordSummary> {
    let sig = records.sig()?;
    let signature = match signer_spk {
        Some(spk) if crate::msg::verify_records(records, spk, canonical).is_ok() => {
            SigStatus::Valid
        }
        Some(_) => SigStatus::Invalid,
        None => SigStatus::Unchecked,
    };
    Some(RecordSummary {
        seq: records.seq().unwrap_or(0),
        flags: sig.flags,
        canonical: sig.canonical.to_string(),
        handle: sig.handle.to_string(),
        signature,
    })
}

/// Best-effort decode of a leaf value into a known type.
fn classify_value(bytes: &[u8]) -> &'static str {
    if bytes.len() == 32 {
        return "CommitmentTip";
    }
    if borsh::from_slice::<spaces_protocol::SpaceOut>(bytes).is_ok() {
        return "SpaceOut";
    }
    if borsh::from_slice::<spaces_nums::NumOut>(bytes).is_ok() {
        return "NumOut";
    }
    if borsh::from_slice::<Commitment>(bytes).is_ok() {
        return "Commitment";
    }
    if crate::cert::HandleOut::from_slice(bytes).is_ok() {
        return "HandleOut";
    }
    "Unknown"
}

/// Build a path entry for a key in a subtree.
fn make_path(
    tree: TreeKind,
    purpose: ProofPurpose,
    provides_root: Option<TreeKind>,
    root: Hash,
    subtree_root: &SubTreeNode,
    key: Hash,
) -> Result<ProofPath, InspectError> {
    let (steps, leaf, resolution) = walk_path::<Sha256Hasher>(subtree_root, &key)?;
    Ok(ProofPath {
        tree,
        purpose,
        root,
        key,
        resolution,
        provides_root,
        commitment: None,
        leaf,
        steps,
    })
}

/// Build a commitment proof path and attach its decoded structure (genesis /
/// prev_root / whether the message receipt directly proves it).
fn commitment_path(
    chain: &ChainProof,
    space: &spaces_protocol::slabel::SLabel,
    commitment_root: Hash,
    nums_root: Hash,
    receipt_final_root: Option<Hash>,
) -> Result<ProofPath, InspectError> {
    let key: Hash = CommitmentKey::new::<KeyHash>(space, commitment_root).into();
    let mut path = make_path(
        TreeKind::NumsRoot,
        ProofPurpose::Commitment,
        Some(TreeKind::HandlesRoot),
        nums_root,
        &chain.nums.0.root,
        key,
    )?;
    if let Ok(Some(c)) = chain.nums.find_commitment(space, commitment_root) {
        path.commitment = Some(CommitmentMeta {
            block_height: c.block_height,
            state_root: c.state_root,
            prev_root: c.prev_root,
            genesis: c.prev_root.is_none(),
            directly_proven: receipt_final_root == Some(c.state_root),
        });
    }
    Ok(path)
}

/// Find the OutpointKey of the SpaceOut for a space in the spaces subtree.
fn find_space_key(
    subtree: &SpacesSubtree,
    space: &spaces_protocol::slabel::SLabel,
) -> Option<Hash> {
    for (k, v) in subtree.iter() {
        if let SpacesValue::UTXO(utxo) = v {
            if utxo
                .space
                .as_ref()
                .is_some_and(|s| s.name.as_ref() == space.as_ref())
            {
                return Some(k);
            }
        }
    }
    None
}

/// Find the key (NumOutpointKey hash) of a NumOut by num_id.
fn find_num_key_by_id(subtree: &NumsSubtree, target: NumId) -> Option<Hash> {
    for (k, v) in subtree.iter() {
        if let NumsValue::UTXO(numout) = v {
            if numout.num.id == target {
                return Some(k);
            }
        }
    }
    None
}

/// Find the key of a NumOut by its SNumeric name.
fn find_num_key_by_numeric(subtree: &NumsSubtree, target: &SNumeric) -> Option<Hash> {
    for (k, v) in subtree.iter() {
        if let NumsValue::UTXO(numout) = v {
            if &numout.num.name == target {
                return Some(k);
            }
        }
    }
    None
}

/// The current script pubkey controlling a space or numeric parent.
fn parent_script_pubkey(
    chain: &ChainProof,
    space: &spaces_protocol::slabel::SLabel,
) -> Option<spaces_protocol::bitcoin::ScriptBuf> {
    if space.is_numeric() {
        let snum: SNumeric = space.clone().try_into().ok()?;
        chain
            .nums
            .find_numeric(&snum)
            .ok()
            .flatten()
            .map(|n| n.script_pubkey)
    } else {
        chain.spaces.find_space(space).map(|s| s.script_pubkey)
    }
}

/// Proof paths for a parent (space or numeric), split by audience.
///
/// `identity` (UTXO ownership + delegate lookup) is shared onto every handle
/// zone under the parent — handles need it to prove ownership and the signer.
/// `tip` (commitment tip pointer + tip commitment) describes the parent's own
/// committed state and stays on the parent zone only; handle zones instead
/// carry their own epoch's commitment.
struct ParentPaths {
    identity: Vec<ProofPath>,
    tip: Vec<ProofPath>,
}

impl ParentPaths {
    /// All paths, for the parent zone itself.
    fn all(&self) -> Vec<ProofPath> {
        let mut v = self.identity.clone();
        v.extend(self.tip.iter().cloned());
        v
    }
}

/// Build paths for a parent (space or numeric) zone: the UTXO, the delegate
/// lookup (parent num_id → NumOut), and the commitment tip + tip commitment.
fn paths_for_parent(
    chain: &ChainProof,
    space: &spaces_protocol::slabel::SLabel,
    spaces_root: Hash,
    nums_root: Option<Hash>,
    receipt_final_root: Option<Hash>,
) -> Result<ParentPaths, InspectError> {
    let mut identity = Vec::new();
    let mut tip = Vec::new();

    if space.is_numeric() {
        // Numeric: only nums tree
        let nums_root_h = nums_root.ok_or(InspectError::IncompleteProof(
            "nums root missing for numeric",
        ))?;
        let snum: SNumeric = space.clone().try_into().expect("numeric");
        if let Some(key) = find_num_key_by_numeric(&chain.nums, &snum) {
            identity.push(make_path(
                TreeKind::NumsRoot,
                ProofPurpose::NumericUtxo,
                None,
                nums_root_h,
                &chain.nums.0.root,
                key,
            )?);
        }
    } else {
        if let Some(key) = find_space_key(&chain.spaces, space) {
            identity.push(make_path(
                TreeKind::SpacesRoot,
                ProofPurpose::SpaceUtxo,
                None,
                spaces_root,
                &chain.spaces.0.root,
                key,
            )?);
        }
    }

    // Delegate lookup: the parent's own spk keyed by num_id. Mirrors
    // `find_num(parent.script_pubkey)` in verification — proves whether the
    // parent has a registered delegate (the signer for temporary handles).
    if let Some(nums_root_h) = nums_root {
        if let Some(spk) = parent_script_pubkey(chain, space) {
            let num_id = NumId::from_spk::<KeyHash>(spk);
            if let Some(key) = find_num_key_by_id(&chain.nums, num_id) {
                identity.push(make_path(
                    TreeKind::NumsRoot,
                    ProofPurpose::DelegateLookup,
                    None,
                    nums_root_h,
                    &chain.nums.0.root,
                    key,
                )?);
            }
        }
    }

    // Commitment tip + tip commitment data (in nums tree)
    if let Some(nums_root_h) = nums_root {
        let tip_key: Hash = CommitmentTipKey::from_slabel::<KeyHash>(space).into();
        let tip_root = chain.nums.get_latest_commitment_root(space).ok().flatten();
        tip.push(make_path(
            TreeKind::NumsRoot,
            ProofPurpose::CommitmentTip,
            None,
            nums_root_h,
            &chain.nums.0.root,
            tip_key,
        )?);
        if let Some(root) = tip_root {
            tip.push(commitment_path(
                chain,
                space,
                root,
                nums_root_h,
                receipt_final_root,
            )?);
        }
    }

    Ok(ParentPaths { identity, tip })
}

/// Build the path for a handle in the operator's epoch handles tree.
fn handle_path(
    handles_root: Hash,
    epoch_tree: &HandleSubtree,
    name: &spaces_protocol::sname::Subname,
    matched_kind: ProofPurpose,
) -> Result<ProofPath, InspectError> {
    let key = Sha256Hasher::hash(name.as_slabel().as_ref());
    make_path(
        TreeKind::HandlesRoot,
        matched_kind,
        None,
        handles_root,
        &epoch_tree.0.root,
        key,
    )
}

/// Build the inspection report for a message and its anchor.
///
/// Does NOT verify the message — callers should call `Veritas::verify` separately
/// if they want validation. This call is read-only structural inspection.
pub fn inspect(veritas: &Veritas, msg: &Message) -> Result<InspectReport, InspectError> {
    let height = msg.chain.anchor.height;
    let anchor = veritas
        .find_anchor(height)
        .ok_or(InspectError::NoAnchorAtHeight(height))?;

    let anchor_info = AnchorInfo {
        block_height: anchor.block.height,
        block_hash: anchor.block.hash.to_byte_array(),
        spaces_root: anchor.spaces_root,
        nums_root: anchor.nums_root,
        anchor_hash: compute_root_id(anchor),
    };

    let mut zones = Vec::new();

    for bundle in &msg.spaces {
        let space = &bundle.subject;
        let parent_handle = SName::from_space(space);

        let receipt = bundle.receipt.as_ref().and_then(receipt_info);
        let receipt_final_root = receipt.as_ref().map(|r| r.final_root);

        let parent_paths = paths_for_parent(
            &msg.chain,
            space,
            anchor.spaces_root,
            anchor.nums_root,
            receipt_final_root,
        )?;

        // Signer keys for record verification, mirroring extract_parent_zone:
        // owner records are signed by the space/num key; delegate records by
        // the delegate key resolved from the nums tree.
        let owner_spk = parent_script_pubkey(&msg.chain, space);
        let delegate_spk = owner_spk
            .as_ref()
            .and_then(|spk| msg.chain.nums.find_num(spk).ok().flatten())
            .map(|n| n.script_pubkey);

        // Parent zone (the space itself): identity + its own tip commitment.
        // The space is on-chain, so it is always Sovereign (matching verify).
        zones.push(ZoneInspect {
            handle: parent_handle.to_string(),
            kind: if space.is_numeric() {
                ZoneKind::Numeric
            } else {
                ZoneKind::Space
            },
            parent: None,
            sovereignty: Some(crate::SovereigntyState::Sovereign),
            receipt: receipt.clone(),
            records: RecordsInfo {
                owner: bundle
                    .records
                    .as_ref()
                    .and_then(|r| record_summary(r, owner_spk.as_ref(), &parent_handle)),
                delegate: bundle
                    .delegate_records
                    .as_ref()
                    .and_then(|r| record_summary(r, delegate_spk.as_ref(), &parent_handle)),
            },
            paths: parent_paths.all(),
        });

        // Handle zones (per epoch, per handle)
        for epoch in &bundle.epochs {
            let handles_root = match epoch.tree.compute_root() {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Per-epoch commitment path: dates this epoch and links its
            // handles_root to the on-chain commitment (mirrors the
            // find_commitment(space, epoch_root) that verification does per
            // epoch). Empty (dependent) epochs have no commitment. This is
            // the epoch's own commitment, which for older epochs differs from
            // the tip commitment shown on the parent zone.
            let epoch_commitment_path = if epoch.tree.0.is_empty() {
                None
            } else if let Some(nums_root_h) = anchor.nums_root {
                Some(commitment_path(
                    &msg.chain,
                    space,
                    handles_root,
                    nums_root_h,
                    receipt_final_root,
                )?)
            } else {
                None
            };

            // This epoch's commitment height, for handle sovereignty. Empty
            // (dependent) epochs have no commitment.
            let epoch_height = if epoch.tree.0.is_empty() {
                None
            } else {
                msg.chain
                    .nums
                    .find_commitment(space, handles_root)
                    .ok()
                    .flatten()
                    .map(|c| c.block_height)
            };

            for h in &epoch.handles {
                let purpose = if h.signature.is_some() {
                    ProofPurpose::HandleExclusion
                } else {
                    ProofPurpose::HandleInclusion
                };
                // Handle zone: parent identity (ownership + delegate) plus this
                // epoch's own commitment — not the parent's tip commitment.
                let mut paths = parent_paths.identity.clone();
                if let Some(path) = &epoch_commitment_path {
                    paths.push(path.clone());
                }
                if let Ok(path) = handle_path(handles_root, &epoch.tree, &h.name, purpose) {
                    paths.push(path);
                }

                // Key rotation lookup (final handle only): nums tree by num_id.
                if h.signature.is_none() {
                    if let Some(nums_root_h) = anchor.nums_root {
                        let num_id = NumId::from_spk::<KeyHash>(h.genesis_spk.clone());
                        if let Some(key) = find_num_key_by_id(&msg.chain.nums, num_id) {
                            paths.push(make_path(
                                TreeKind::NumsRoot,
                                ProofPurpose::KeyRotation,
                                None,
                                nums_root_h,
                                &msg.chain.nums.0.root,
                                key,
                            )?);
                        }
                    }
                }

                let subject = match spaces_protocol::sname::SName::join(&h.name, space) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                // Sovereignty mirrors verification: temporary handles and
                // handles in an empty (uncommitted) epoch are Dependent;
                // committed handles inherit their epoch's finality.
                let sovereignty = if h.signature.is_some() || epoch.tree.0.is_empty() {
                    crate::SovereigntyState::Dependent
                } else {
                    epoch_height
                        .map(|hgt| veritas.sovereignty_for(hgt))
                        .unwrap_or(crate::SovereigntyState::Pending)
                };

                // Record signer key, mirroring verify_{temporary,final}_handle:
                // temporary handles are signed by the genesis key; final
                // handles by the rotated key from the nums tree (genesis
                // fallback when no rotation is present).
                let record_spk = if h.signature.is_some() {
                    Some(h.genesis_spk.clone())
                } else {
                    msg.chain
                        .nums
                        .find_num(&h.genesis_spk)
                        .ok()
                        .flatten()
                        .map(|n| n.script_pubkey)
                        .or_else(|| Some(h.genesis_spk.clone()))
                };

                zones.push(ZoneInspect {
                    handle: subject.to_string(),
                    kind: ZoneKind::Handle,
                    parent: Some(parent_handle.to_string()),
                    sovereignty: Some(sovereignty),
                    receipt: None,
                    records: RecordsInfo {
                        owner: h
                            .records
                            .as_ref()
                            .and_then(|r| record_summary(r, record_spk.as_ref(), &subject)),
                        delegate: None,
                    },
                    paths,
                });
            }
        }
    }

    Ok(InspectReport {
        anchor: anchor_info,
        zones,
    })
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            bytes.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            hex::decode(&s).map_err(serde::de::Error::custom)
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
}
