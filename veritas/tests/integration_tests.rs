use bitcoin::hashes::{Hash as BitcoinHash, sha256, HashEngine};
use bitcoin::key::Keypair;
use bitcoin::key::rand::Rng;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::rand;
use bitcoin::{BlockHash, OutPoint, ScriptBuf, Txid};
use borsh::{BorshDeserialize, BorshSerialize};
use libveritas::cert::{Certificate, HandleSubtree, KeyHash, PtrsSubtree, Signature, SpacesSubtree, Witness};
use spacedb::Sha256Hasher;
use spacedb::subtree::{ProofType, SubTree, ValueOrHash};
use spaces_protocol::hasher::{KeyHasher, OutpointKey, SpaceKey};
use spaces_protocol::slabel::SLabel;
use spaces_protocol::{Covenant, FullSpaceOut, Space, SpaceOut};
use spaces_ptr::sptr::Sptr;
use spaces_ptr::{rolling_hash, CommitmentKey, FullPtrOut, Ptr, PtrOut, PtrOutpointKey, RegistryKey, RegistrySptrKey, RootAnchor};
use std::collections::HashMap;
use std::str::FromStr;
use risc0_zkvm::{FakeReceipt, InnerReceipt, Receipt, ReceiptClaim};
use spaces_protocol::constants::ChainAnchor;
use spaces_ptr::constants::COMMITMENT_FINALITY_INTERVAL;
use libveritas::{hash_signable_message, ProvableOption, SovereigntyState, Veritas, Zone};
use libveritas::msg::{self, Message, QueryContext};
use libveritas::sname::{Label, SName};

fn sname(s: &str) -> SName {
    SName::from_str(s).unwrap()
}

fn slabel(s: &str) -> SLabel {
    SLabel::from_str(s).unwrap()
}

fn label(s: &str) -> Label {
    Label::from_str(s).unwrap()
}

fn sign_zone(zone: &Zone, keypair: &Keypair) -> Signature {
    let msg = hash_signable_message(&zone.signing_bytes());
    let secp = Secp256k1::new();
    let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
    Signature(sig.serialize())
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct EncodableOutpoint(
    #[borsh(
        serialize_with = "borsh_utils::serialize_outpoint",
        deserialize_with = "borsh_utils::deserialize_outpoint"
    )]
    pub OutPoint,
);

fn gen_p2tr_spk() -> (ScriptBuf, Keypair) {
    use bitcoin::script::Builder;
    use bitcoin::opcodes::all::OP_PUSHNUM_1;

    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _parity) = public_key.x_only_public_key();

    // Build witness v1 script with untweaked pubkey (no taproot tweak)
    let script = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(xonly.serialize())
        .into_script();

    (script, keypair)
}

#[derive(Clone)]
pub struct TestSpace {
    pub fso: FullSpaceOut,
    pub keypair: Keypair,
}

#[derive(Clone)]
pub struct TestPtr {
    pub fso: FullPtrOut,
    pub keypair: Keypair,
}

impl TestSpace {
    pub fn new(name: &str, block_height: u32) -> Self {
        let mut rng = rand::thread_rng();
        let mut txid_bytes = [0u8; 32];
        rng.fill(&mut txid_bytes);

        let txid = Txid::from_slice(&txid_bytes).expect("valid txid");
        let n: u32 = rng.r#gen();
        let (script_pubkey, keypair) = gen_p2tr_spk();

        let fso = FullSpaceOut {
            txid,
            spaceout: SpaceOut {
                n: n as usize,
                space: Some(Space {
                    name: slabel(name),
                    covenant: Covenant::Transfer {
                        expire_height: block_height + spaces_protocol::constants::RENEWAL_INTERVAL,
                        data: None,
                    },
                }),
                value: Default::default(),
                script_pubkey,
            },
        };

        TestSpace { fso, keypair }
    }

    pub fn label(&self) -> SLabel {
        self.fso
            .spaceout
            .space
            .as_ref()
            .expect("valid space")
            .name
            .clone()
    }

    pub fn outpoint_key(&self) -> OutpointKey {
        OutpointKey::from_outpoint::<KeyHash>(self.fso.outpoint())
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.fso.spaceout.script_pubkey.clone()
    }

    pub fn space_key(&self) -> SpaceKey {
        SpaceKey::from(KeyHash::hash(self.label().as_ref()))
    }

    pub fn spaceout_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self.fso.spaceout).expect("valid")
    }

    pub fn outpoint_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&EncodableOutpoint(self.fso.outpoint())).expect("valid")
    }
}

impl TestPtr {
    pub fn new(genesis_spk: ScriptBuf, block_height: u32) -> Self {
        let sptr = Sptr::from_spk::<KeyHash>(genesis_spk);

        let mut rng = rand::thread_rng();
        let mut txid_bytes = [0u8; 32];
        rng.fill(&mut txid_bytes);

        let txid = Txid::from_slice(&txid_bytes).expect("valid txid");
        let n: u32 = rng.r#gen();
        let (script_pubkey, keypair) = gen_p2tr_spk();

        let fso = FullPtrOut {
            txid,
            ptrout: PtrOut {
                n: n as usize,
                sptr: Some(Ptr {
                    id: sptr,
                    data: None,
                    last_update: block_height,
                }),
                value: Default::default(),
                script_pubkey,
            },
        };

        TestPtr { fso, keypair }
    }

    pub fn sptr(&self) -> Sptr {
        self.fso.ptrout.sptr.as_ref().expect("valid").id.clone()
    }

    pub fn outpoint_key(&self) -> PtrOutpointKey {
        PtrOutpointKey::from_outpoint::<KeyHash>(self.fso.outpoint())
    }

    pub fn ptrout_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self.fso.ptrout).expect("valid")
    }

    pub fn outpoint_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&EncodableOutpoint(self.fso.outpoint())).expect("valid")
    }
}

#[derive(Clone)]
pub struct TestChain {
    pub spaces_tree: SubTree<Sha256Hasher>,
    pub ptrs_tree: SubTree<Sha256Hasher>,
    pub spaces: HashMap<SLabel, TestSpace>,
    pub ptrs: HashMap<Sptr, TestPtr>,
    pub block_height: u32,
}

pub struct TestHandleTree {
    pub space: SLabel,
    pub ds: TestDelegatedSpace,
    pub handle_tree: SubTree<Sha256Hasher>,
    pub commitments: Vec<TestCommitmentBundle>,
    pub staged: HashMap<Label, StagedHandle>,
}

pub struct StagedHandle {
    pub handle: TestHandle,
    pub signature: Signature,
}

pub struct TestCommitmentBundle {
    root: [u8;32],
    block_height: u32,
    handles: HashMap<Label, TestHandle>,
    handle_tree: SubTree<Sha256Hasher>,
    receipt: Option<Receipt>,
}

impl TestChain {
    pub fn new() -> Self {
        Self {
            spaces_tree: SubTree::empty(),
            ptrs_tree: SubTree::empty(),
            spaces: Default::default(),
            ptrs: Default::default(),
            block_height: 0,
        }
    }

    pub fn increase_time(&mut self, n: u32) {
        self.block_height += n;
    }

    pub fn add_space(&mut self, name: &str) -> TestSpace {
        let space = TestSpace::new(name, self.block_height);
        assert!(!self.spaces.contains_key(&space.label()));

        // insert outpoint -> spaceout mapping
        self.spaces_tree
            .insert(
                space.outpoint_key().into(),
                ValueOrHash::Value(space.spaceout_bytes()),
            )
            .expect("insert space");
        // insert space -> outpoint mapping
        self.spaces_tree
            .insert(
                space.space_key().into(),
                ValueOrHash::Value(space.outpoint_bytes()),
            )
            .expect("insert outpoint");
        self.spaces.insert(space.label(), space.clone());

        space
    }

    pub fn current_root_anchor(&self) -> RootAnchor {
        let spaces_root = self.spaces_tree.compute_root().expect("spaces root");
        let ptrs_root = self.ptrs_tree.compute_root().expect("ptrs root");

        let block_hash = BlockHash
        ::from_byte_array(rolling_hash::<KeyHash>(spaces_root, ptrs_root));

        RootAnchor {
            spaces_root,
            ptrs_root: Some(ptrs_root),
            block: ChainAnchor {
                hash: block_hash,
                height: self.block_height,
            },
        }
    }

    pub fn add_ptr(&mut self, genesis_spk: ScriptBuf) -> TestPtr {
        let ptr = TestPtr::new(genesis_spk, self.block_height);
        assert!(!self.ptrs.contains_key(&ptr.sptr()));

        // Insert outpoint -> ptrout mapping
        self.ptrs_tree
            .insert(
                ptr.outpoint_key().into(),
                ValueOrHash::Value(ptr.ptrout_bytes()),
            )
            .expect("insert ptr");

        // Insert Sptr -> outpoint mapping
        self.ptrs_tree
            .insert(ptr.sptr().into(), ValueOrHash::Value(ptr.outpoint_bytes()))
            .expect("insert outpoint");
        self.ptrs.insert(ptr.sptr().into(), ptr.clone());
        ptr
    }

    pub fn add_space_with_delegation(&mut self, name: &str) -> TestDelegatedSpace {
        let space = self.add_space(name);
        let ptr = self.add_ptr(space.script_pubkey());

        // insert Sptr -> Space mapping
        let registry_sptr_key = RegistrySptrKey::from_sptr::<KeyHash>(ptr.sptr());
        self.ptrs_tree
            .insert(
                registry_sptr_key.into(),
                ValueOrHash::Value(space.label().as_ref().to_vec()),
            )
            .expect("insert registry sptr key");

        TestDelegatedSpace { space, ptr }
    }

    pub fn insert_commitment(&mut self, ds: &TestDelegatedSpace, root: [u8; 32]) -> spaces_ptr::Commitment {
        let prev_finalized = self
            .rollback_to_finalized_commitment(&ds.space.label());

        let commitment = match prev_finalized {
            None => spaces_ptr::Commitment {
                state_root: root,
                prev_root: None,
                rolling_hash: root,
                block_height: self.block_height,
            },
            Some(prev) => spaces_ptr::Commitment {
                state_root: root,
                prev_root: Some(prev.state_root),
                rolling_hash: rolling_hash::<KeyHash>(prev.rolling_hash, root),
                block_height: self.block_height,
            }
        };

        let commitment_key = CommitmentKey::new::<KeyHash>(&ds.space.label(), root);

        let commitment_bytes = borsh::to_vec(&commitment).expect("valid");

        self.ptrs_tree.insert(commitment_key.into(), ValueOrHash::Value(commitment_bytes))
            .expect("insert commitment");
        let registry_key = RegistryKey::from_slabel::<KeyHash>(&ds.space.label());
        self.ptrs_tree.update(registry_key.into(), ValueOrHash::Value(commitment.state_root.to_vec()))
            .expect("insert registry");

        commitment
    }

    // If no root specified, will get the tip
    pub fn get_commitment(
        &self,
        space: &SLabel,
        root: Option<[u8; 32]>,
    ) -> Option<spaces_ptr::Commitment> {
        let root = match root {
            Some(root) => Some(root),
            None => {
                let registry_key = RegistryKey::from_slabel::<KeyHash>(space);
                let rkh: [u8; 32] = registry_key.into();
                self.ptrs_tree
                    .iter()
                    .find(|(k, _)| **k == rkh)
                    .map(|(_, v)| {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(v);
                        h
                    })
            }
        }?;

        let commitment_key = CommitmentKey::new::<KeyHash>(space, root);
        let ckh: [u8; 32] = commitment_key.into();
        self.ptrs_tree
            .iter()
            .find(|(k, _)| **k == ckh)
            .map(|(_, v)| {
                let commitment: spaces_ptr::Commitment =
                    borsh::from_slice(v).expect("valid commitment");
                commitment
            })
    }

    pub fn rollback_to_finalized_commitment(&mut self, space: &SLabel) -> Option<spaces_ptr::Commitment> {
        let commitment = self.get_commitment(space, None)?;
        if commitment.is_finalized(self.block_height) {
            return Some(commitment);
        }

        // it's not finalized, so delete it
        let registry_key = RegistryKey::from_slabel::<KeyHash>(space);
        let commitment_key = CommitmentKey::new::<KeyHash>(space, commitment.state_root);
        let mut ptrs_tree = self.ptrs_tree.clone();
        ptrs_tree = ptrs_tree.delete(&registry_key.into()).expect("delete");
        ptrs_tree = ptrs_tree.delete(&commitment_key.into()).expect("delete");
        self.ptrs_tree = ptrs_tree;

        // there can only be one unfinalized commitment, so prev is finalized if it exists
        let prev_root = commitment.prev_root?;
        let finalized = self.get_commitment(space, Some(prev_root))?;

        // update tip pointer
        self.ptrs_tree.update(registry_key.into(), ValueOrHash::Value(finalized.state_root.to_vec()))
            .expect("update");

        Some(finalized)
    }
}

pub struct TestHandle {
    pub name: Label,
    pub genesis_spk: ScriptBuf,
    pub keypair: Keypair
}

impl TestHandleTree {
    pub fn new(ds: &TestDelegatedSpace) -> Self {
        Self {
            space: ds.space.label(),
            ds: ds.clone(),
            handle_tree: SubTree::empty(),
            commitments: vec![],
            staged: Default::default(),
        }
    }

    pub fn add_handle(&mut self, name: &str) {
        let label = label(name);
        let label_hash = KeyHash::hash(label.as_slabel().as_ref());
        assert!(
            !self.handle_tree.contains(&label_hash).expect("complete tree"),
            "already exists"
        );
        assert!(!self.staged.contains_key(&label), "already staged");

        let (genesis_spk, keypair) = gen_p2tr_spk();
        let handle = TestHandle {
            name: label,
            genesis_spk: genesis_spk.clone(),
            keypair,
        };

        let zone = Zone {
            anchor: 0,
            sovereignty: SovereigntyState::Dependent,
            handle: sname(&format!("{}{}", name, self.space)),
            script_pubkey: genesis_spk,
            data: None,
            offchain_data: None,
            delegate: ProvableOption::Unknown,
            commitment: ProvableOption::Unknown,
        };

        let signature = sign_zone(&zone, &self.ds.ptr.keypair);
        let staged = StagedHandle {
            handle,
            signature,
        };

        self.staged.insert(staged.handle.name.clone(), staged);
    }

    pub fn commit(&mut self, chain: &mut TestChain) {
        assert!(!self.staged.is_empty(), "no handles to commit");

        let initial_root = self.handle_tree.compute_root().expect("compute root");
        let handles: HashMap<Label, TestHandle> = std::mem::take(&mut self.staged)
            .into_iter()
            .map(|(k, v)| (k, v.handle))
            .collect();

        for (_, handle) in handles.iter() {
            let handle_key = KeyHash::hash(handle.name.as_slabel().as_ref());
            let spk = handle.genesis_spk.clone();
            self.handle_tree
                .insert(handle_key, ValueOrHash::Value(spk.to_bytes()))
                .expect("insert handle");
        }

        let final_root = self.handle_tree.compute_root().expect("compute root");
        let onchain_commitment = chain.insert_commitment(&self.ds, final_root);

        let receipt = if onchain_commitment.prev_root.is_some() {
            let commitment = libveritas_zk::guest::Commitment {
                space: KeyHash::hash(self.space.as_ref()),
                policy_step: libveritas_methods::STEP_ID,
                policy_fold: libveritas_methods::FOLD_ID,
                initial_root,
                final_root,
                rolling_hash: onchain_commitment.rolling_hash,
                kind: libveritas_zk::guest::CommitmentKind::Fold,
            };


            // Serialize using risc0 serde format (u32 words → le bytes),
            // matching what a real guest would write via env::commit()
            let words = risc0_zkvm::serde::to_vec(&commitment).expect("serialize commitment");
            let journal_bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();

            let receipt_claim = ReceiptClaim::ok(libveritas_methods::FOLD_ID, journal_bytes.clone());
            Some(
                Receipt::new(InnerReceipt::Fake(FakeReceipt::new(receipt_claim)), journal_bytes)
            )
        } else {
            None
        };

        self.commitments.push(TestCommitmentBundle {
            root: final_root,
            block_height: onchain_commitment.block_height,
            handles,
            handle_tree: self.handle_tree.clone(),
            receipt,
        })
    }

    /// Build a Message with proved (pruned) Merkle proofs.
    ///
    /// * `chain` - The chain snapshot at the anchor time (must match anchor roots)
    /// * `commitment_idx` - Which commitment to include
    /// * `handle_names` - Handle subjects to include (empty for root-only)
    /// * `anchor` - The chain anchor for the message
    pub fn build_message(
        &self,
        chain: &TestChain,
        commitment_idx: usize,
        handle_names: &[&str],
        anchor: &ChainAnchor,
    ) -> Message {
        let tcb = &self.commitments[commitment_idx];

        // --- Spaces tree keys ---
        let spaces_keys: Vec<[u8; 32]> = vec![
            self.ds.space.outpoint_key().into(),
            self.ds.space.space_key().into(),
        ];

        // --- Ptrs tree keys ---
        let mut ptrs_keys: Vec<[u8; 32]> = vec![
            self.ds.ptr.outpoint_key().into(),
            self.ds.ptr.sptr().into(),
        ];

        // Registry key (commitment tip pointer)
        ptrs_keys.push(RegistryKey::from_slabel::<KeyHash>(&self.space).into());

        // Commitment key for the commitment being proven
        ptrs_keys.push(CommitmentKey::new::<KeyHash>(&self.space, tcb.root).into());

        // --- Handle tree keys + handles ---
        let mut handle_keys: Vec<[u8; 32]> = Vec::new();
        let mut handles: Vec<msg::Handle> = Vec::new();

        for &name in handle_names {
            let l = label(name);
            let label_hash = KeyHash::hash(l.as_slabel().as_ref());
            handle_keys.push(label_hash);

            // Find handle across all commitments up to this one
            let handle = self.commitments[..=commitment_idx]
                .iter()
                .find_map(|c| c.handles.get(&l))
                .expect("handle must exist in a previous commitment");

            // Handle's sptr for key rotation lookup (proves non-existence in ptrs tree)
            let handle_sptr = Sptr::from_spk::<KeyHash>(handle.genesis_spk.clone());
            ptrs_keys.push(handle_sptr.into());

            handles.push(msg::Handle {
                name: l,
                genesis_spk: handle.genesis_spk.clone(),
                data: None,
                signature: None, // Final cert - no signature
            });
        }

        // --- Create proved subtrees ---
        let spaces_proof = chain
            .spaces_tree
            .prove(&spaces_keys, ProofType::Standard)
            .expect("prove spaces");
        let ptrs_proof = chain
            .ptrs_tree
            .prove(&ptrs_keys, ProofType::Standard)
            .expect("prove ptrs");
        let handles_proof = tcb
            .handle_tree
            .prove(&handle_keys, ProofType::Standard)
            .expect("prove handles");

        // --- Build message ---
        Message {
            anchor: anchor.clone(),
            chain: msg::ChainProof {
                spaces: SpacesSubtree(spaces_proof),
                ptrs: PtrsSubtree(ptrs_proof),
            },
            spaces: vec![msg::Bundle {
                space: self.space.clone(),
                receipt: tcb.receipt.clone(),
                epochs: vec![msg::Epoch {
                    tree: HandleSubtree(handles_proof),
                    handles,
                }],
                offchain_data: None,
                delegate_offchain_data: None,
            }],
        }
    }

    /// Build a temporary certificate message for a staged (uncommitted) handle.
    ///
    /// The handle must be in `staged`. The message includes an exclusion proof
    /// (handle not in tree) and the pre-computed signature from the delegate.
    pub fn build_temporary_message(
        &self,
        chain: &TestChain,
        commitment_idx: usize,
        handle_name: &str,
        anchor: &ChainAnchor,
    ) -> Message {
        let tcb = &self.commitments[commitment_idx];
        let staged = self.staged.get(&label(handle_name))
            .expect("handle must be staged");

        // --- Spaces tree keys ---
        let spaces_keys: Vec<[u8; 32]> = vec![
            self.ds.space.outpoint_key().into(),
            self.ds.space.space_key().into(),
        ];

        // --- Ptrs tree keys ---
        let mut ptrs_keys: Vec<[u8; 32]> = vec![
            self.ds.ptr.outpoint_key().into(),
            self.ds.ptr.sptr().into(),
        ];
        ptrs_keys.push(RegistryKey::from_slabel::<KeyHash>(&self.space).into());
        ptrs_keys.push(CommitmentKey::new::<KeyHash>(&self.space, tcb.root).into());

        // Handle's sptr for key rotation (exclusion proof — handle never on-chain)
        let handle_sptr = Sptr::from_spk::<KeyHash>(staged.handle.genesis_spk.clone());
        ptrs_keys.push(handle_sptr.into());

        // --- Handle exclusion proof ---
        let handle_key = KeyHash::hash(staged.handle.name.as_slabel().as_ref());
        let handle_keys: Vec<[u8; 32]> = vec![handle_key];

        // --- Create proved subtrees ---
        let spaces_proof = chain.spaces_tree
            .prove(&spaces_keys, ProofType::Standard)
            .expect("prove spaces");
        let ptrs_proof = chain.ptrs_tree
            .prove(&ptrs_keys, ProofType::Standard)
            .expect("prove ptrs");
        let handles_proof = tcb.handle_tree
            .prove(&handle_keys, ProofType::Standard)
            .expect("prove handles exclusion");

        Message {
            anchor: anchor.clone(),
            chain: msg::ChainProof {
                spaces: SpacesSubtree(spaces_proof),
                ptrs: PtrsSubtree(ptrs_proof),
            },
            spaces: vec![msg::Bundle {
                space: self.space.clone(),
                receipt: tcb.receipt.clone(),
                epochs: vec![msg::Epoch {
                    tree: HandleSubtree(handles_proof),
                    handles: vec![msg::Handle {
                        name: staged.handle.name.clone(),
                        genesis_spk: staged.handle.genesis_spk.clone(),
                        data: None,
                        signature: Some(staged.signature),
                    }],
                }],
                offchain_data: None,
                delegate_offchain_data: None,
            }],
        }
    }
}

#[derive(Clone)]
pub struct TestDelegatedSpace {
    pub space: TestSpace,
    pub ptr: TestPtr,
}

/// Shared test fixture: a delegated space (@bitcoin) with two commitments.
///
/// Commitment 0: alice + bob  (finalized, no receipt needed)
/// Commitment 1: charlie      (pending, has ZK receipt)
struct Fixture {
    finalized_chain: TestChain,
    latest_chain: TestChain,
    handles: TestHandleTree,
    finalized_anchor: RootAnchor,
    latest_anchor: RootAnchor,
}

impl Fixture {
    fn new() -> Self {
        let mut chain = TestChain::new();
        let ds = chain.add_space_with_delegation("@bitcoin");

        let mut handles = TestHandleTree::new(&ds);
        handles.add_handle("alice");
        handles.add_handle("bob");
        handles.commit(&mut chain);

        chain.increase_time(COMMITMENT_FINALITY_INTERVAL + 1);
        let finalized_anchor = chain.current_root_anchor();
        let finalized_chain = chain.clone();

        chain.increase_time(1);
        handles.add_handle("charlie");
        handles.commit(&mut chain);
        let latest_anchor = chain.current_root_anchor();

        // add a staged handle for temporary cert testing
        handles.add_handle("staged");

        Fixture {
            finalized_chain,
            latest_chain: chain,
            handles,
            finalized_anchor,
            latest_anchor,
        }
    }

    fn veritas(&self) -> Veritas {
        let anchors = vec![self.latest_anchor.clone(), self.finalized_anchor.clone()];
        let mut v = Veritas::from_anchors(anchors).expect("valid anchors");
        v.set_dev_mode(true);
        v
    }

    /// Message proving commitment 0 (finalized) against the finalized anchor.
    fn finalized_message(&self, handles: &[&str]) -> Message {
        self.handles.build_message(
            &self.finalized_chain, 0, handles,
            &self.finalized_anchor.block,
        )
    }

    /// Message proving commitment 1 (pending) against the latest anchor.
    fn pending_message(&self, handles: &[&str]) -> Message {
        self.handles.build_message(
            &self.latest_chain, 1, handles,
            &self.latest_anchor.block,
        )
    }

    /// Temporary certificate message for a staged handle (not yet committed).
    fn temporary_message(&self, handle_name: &str) -> Message {
        self.handles.build_temporary_message(
            &self.latest_chain, 1, handle_name,
            &self.latest_anchor.block,
        )
    }
}

#[test]
fn verify_root_finalized() {
    let f = Fixture::new();
    let veritas = f.veritas();
    let ctx = QueryContext::new();

    let result = veritas.verify_message(&ctx, f.finalized_message(&[])).expect("verify");

    assert_eq!(result.zones.len(), 1);
    let zone = &result.zones[0];
    assert_eq!(zone.handle, sname("@bitcoin"));
    assert!(matches!(zone.sovereignty, SovereigntyState::Sovereign));
    let ProvableOption::Exists { value: c } = &zone.commitment else {
        panic!("expected commitment Exists");
    };
    assert_eq!(c.onchain.state_root, f.handles.commitments[0].root);
    assert!(c.receipt_hash.is_none()); // First commitment, no receipt needed
    assert!(matches!(zone.delegate, ProvableOption::Exists { .. }));
}

#[test]
fn verify_leaf_finalized() {
    let f = Fixture::new();
    let veritas = f.veritas();
    let ctx = QueryContext::new();

    let result = veritas.verify_message(&ctx, f.finalized_message(&["alice"])).expect("verify");

    // Should have root zone + alice zone
    assert_eq!(result.zones.len(), 2);
    let alice = result.zones.iter().find(|z| z.handle == sname("alice@bitcoin")).expect("alice");
    assert!(matches!(alice.sovereignty, SovereigntyState::Sovereign));

    let result = veritas.verify_message(&ctx, f.finalized_message(&["bob"])).expect("verify");
    let bob = result.zones.iter().find(|z| z.handle == sname("bob@bitcoin")).expect("bob");
    assert!(matches!(bob.sovereignty, SovereigntyState::Sovereign));
}

#[test]
fn verify_root_pending() {
    let f = Fixture::new();
    let veritas = f.veritas();
    let ctx = QueryContext::new();

    let result = veritas.verify_message(&ctx, f.pending_message(&[])).expect("verify");

    assert_eq!(result.zones.len(), 1);
    let zone = &result.zones[0];
    assert!(matches!(zone.sovereignty, SovereigntyState::Pending));
    let ProvableOption::Exists { value: c } = &zone.commitment else {
        panic!("expected commitment Exists");
    };
    assert_eq!(c.onchain.state_root, f.handles.commitments[1].root);
    assert!(c.receipt_hash.is_some()); // Non-first commitment, receipt verified
}

#[test]
fn verify_leaf_pending() {
    let f = Fixture::new();
    let veritas = f.veritas();
    let ctx = QueryContext::new();

    let result = veritas.verify_message(&ctx, f.pending_message(&["charlie"])).expect("verify");
    let charlie = result.zones.iter().find(|z| z.handle == sname("charlie@bitcoin")).expect("charlie");
    assert!(matches!(charlie.sovereignty, SovereigntyState::Pending));
}

#[test]
fn verify_leaf_across_anchors() {
    let f = Fixture::new();
    let veritas = f.veritas();
    let ctx = QueryContext::new();

    // alice was committed in commitment 0, verified against the latest anchor
    let result = veritas.verify_message(&ctx, f.pending_message(&["alice"])).expect("verify");
    let alice = result.zones.iter().find(|z| z.handle == sname("alice@bitcoin")).expect("alice");
    assert_eq!(alice.handle, sname("alice@bitcoin"));
}

#[test]
fn verify_leaf_temporary() {
    let f = Fixture::new();
    let veritas = f.veritas();
    let ctx = QueryContext::new();

    // "staged" is in staged but not committed — uses delegate's signature
    let result = veritas.verify_message(&ctx, f.temporary_message("staged")).expect("verify");
    let staged = result.zones.iter().find(|z| z.handle == sname("staged@bitcoin")).expect("staged");
    assert_eq!(staged.handle, sname("staged@bitcoin"));
    assert!(matches!(staged.sovereignty, SovereigntyState::Dependent));
}

#[test]
fn verify_with_request_filter() {
    let f = Fixture::new();
    let veritas = f.veritas();

    // Request only alice, not the root
    let mut ctx = QueryContext::new();
    ctx.add_request(sname("alice@bitcoin"));

    let result = veritas.verify_message(&ctx, f.finalized_message(&["alice", "bob"])).expect("verify");

    // Should only return alice (root not requested, bob not requested)
    assert_eq!(result.zones.len(), 1);
    assert_eq!(result.zones[0].handle, sname("alice@bitcoin"));
}

#[test]
fn verify_with_cached_parent_zone() {
    let f = Fixture::new();
    let veritas = f.veritas();

    // First verify to get parent zone
    let ctx = QueryContext::new();
    let result = veritas.verify_message(&ctx, f.finalized_message(&[])).expect("verify");
    let parent_zone = result.zones[0].clone();

    // Now verify with cached parent
    let ctx = QueryContext::from_zones(vec![parent_zone]);
    let result = veritas.verify_message(&ctx, f.finalized_message(&["alice"])).expect("verify");

    // Should succeed and include alice
    let alice = result.zones.iter().find(|z| z.handle == sname("alice@bitcoin")).expect("alice");
    assert_eq!(alice.handle, sname("alice@bitcoin"));
}

#[test]
fn verify_uses_better_cached_zone() {
    let f = Fixture::new();
    let veritas = f.veritas();

    // Create a "worse" cached zone with lower anchor
    let cached_zone = Zone {
        anchor: 0, // Lower than actual anchor
        sovereignty: SovereigntyState::Dependent,
        handle: sname("alice@bitcoin"),
        script_pubkey: ScriptBuf::new(),
        data: None,
        offchain_data: None,
        delegate: ProvableOption::Unknown,
        commitment: ProvableOption::Unknown,
    };

    let ctx = QueryContext::from_zones(vec![cached_zone.clone()]);
    let result = veritas.verify_message(&ctx, f.finalized_message(&["alice"])).expect("verify");

    // Should return the newly verified zone (better anchor)
    let alice = result.zones.iter().find(|z| z.handle == sname("alice@bitcoin")).expect("alice");
    assert!(alice.anchor > 0);
    assert!(matches!(alice.sovereignty, SovereigntyState::Sovereign));
}

#[test]
fn certificate_iterator() {
    let f = Fixture::new();
    let veritas = f.veritas();
    let ctx = QueryContext::new();

    // Verify root + two leaves
    let result = veritas.verify_message(&ctx, f.finalized_message(&["alice", "bob"])).expect("verify");

    let certs: Vec<Certificate> = result.certificates().collect();

    // Should have 3 certs: root, alice, bob
    assert_eq!(certs.len(), 3);

    // First should be root
    assert_eq!(certs[0].subject, sname("@bitcoin"));
    assert!(matches!(certs[0].witness, Witness::Root { .. }));

    // Then leaves
    let alice_cert = certs.iter().find(|c| c.subject == sname("alice@bitcoin")).expect("alice cert");
    assert!(matches!(alice_cert.witness, Witness::Leaf { .. }));

    let bob_cert = certs.iter().find(|c| c.subject == sname("bob@bitcoin")).expect("bob cert");
    assert!(matches!(bob_cert.witness, Witness::Leaf { .. }));
}

#[test]
fn certificate_iterator_leaves_only() {
    let f = Fixture::new();
    let veritas = f.veritas();

    // Request only alice, not the root
    let mut ctx = QueryContext::new();
    ctx.add_request(sname("alice@bitcoin"));

    let result = veritas.verify_message(&ctx, f.finalized_message(&["alice"])).expect("verify");

    let certs: Vec<Certificate> = result.certificates().collect();

    // Should have only alice (no root since it wasn't requested)
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].subject, sname("alice@bitcoin"));
    assert!(matches!(certs[0].witness, Witness::Leaf { .. }));
}
