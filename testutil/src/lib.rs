//! Test utilities for libveritas.
//!
//! Provides simulated chain state and handle trees for testing certificate
//! verification without a real blockchain.

pub mod fixture;

use bitcoin::hashes::{Hash as BitcoinHash};
use bitcoin::key::Keypair;
use bitcoin::key::rand::Rng;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::rand::{self, SeedableRng};
use bitcoin::{BlockHash, OutPoint, ScriptBuf, Txid};
use borsh::{BorshDeserialize, BorshSerialize};
use libveritas::cert::{HandleSubtree, KeyHash, PtrsSubtree, Signature, SpacesSubtree};
use libveritas::msg::{self, ChainProof, Message, OffchainData};
use libveritas::sname::{Label, SName};
use libveritas::{ProvableOption, SovereigntyState, Veritas, Zone, hash_signable_message};
use risc0_zkvm::{FakeReceipt, InnerReceipt, Receipt, ReceiptClaim};
use spacedb::Sha256Hasher;
use spacedb::subtree::{ProofType, SubTree, ValueOrHash};
use spaces_protocol::constants::{ChainAnchor};
use spaces_protocol::hasher::{KeyHasher, OutpointKey, SpaceKey};
use spaces_protocol::slabel::SLabel;
use spaces_protocol::{Bytes, Covenant, FullSpaceOut, Space, SpaceOut};
use spaces_ptr::sptr::Sptr;
use spaces_ptr::{
    CommitmentKey, FullPtrOut, Ptr, PtrOut, PtrOutpointKey, RegistryKey, RegistrySptrKey,
    RootAnchor, rolling_hash,
};
use std::collections::HashMap;
use std::str::FromStr;
// ─────────────────────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────────────────────

pub fn sname(s: &str) -> SName {
    SName::from_str(s).unwrap()
}

pub fn sign_mesage(signable: &[u8], keypair: &Keypair) -> Signature {
    let msg = hash_signable_message(signable);
    let secp = Secp256k1::new();
    let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
    Signature(sig.serialize())
}

pub fn slabel(s: &str) -> SLabel {
    SLabel::from_str(s).unwrap()
}

pub fn label(s: &str) -> Label {
    Label::from_str(s).unwrap()
}

pub fn sign_zone(zone: &Zone, keypair: &Keypair) -> Signature {
    sign_mesage(&zone.signing_bytes(), &keypair)
}

pub fn gen_p2tr_spk() -> (ScriptBuf, Keypair) {
    use bitcoin::opcodes::all::OP_PUSHNUM_1;
    use bitcoin::script::Builder;

    let mut rng = rng();
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly, _parity) = public_key.x_only_public_key();

    let script = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(xonly.serialize())
        .into_script();

    (script, keypair)
}

// ─────────────────────────────────────────────────────────────────────────────
// Borsh helper for OutPoint
// ─────────────────────────────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize)]
pub struct EncodableOutpoint(
    #[borsh(
        serialize_with = "borsh_utils::serialize_outpoint",
        deserialize_with = "borsh_utils::deserialize_outpoint"
    )]
    pub OutPoint,
);

// ─────────────────────────────────────────────────────────────────────────────
// Test primitives
// ─────────────────────────────────────────────────────────────────────────────

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

#[derive(Clone)]
pub struct TestDelegatedSpace {
    pub space: TestSpace,
    pub ptr: TestPtr,
}

#[derive(Clone)]
pub struct TestHandle {
    pub name: Label,
    pub genesis_spk: ScriptBuf,
    pub keypair: Keypair,
    pub offchain_data: Option<OffchainData>,
}

#[derive(Clone)]
pub struct StagedHandle {
    pub handle: TestHandle,
    pub signature: Signature,
}

#[derive(Clone)]
pub struct TestCommitmentBundle {
    pub root: [u8; 32],
    pub block_height: u32,
    pub handles: HashMap<Label, TestHandle>,
    pub handle_tree: SubTree<Sha256Hasher>,
    pub receipt: Option<Receipt>,
}

fn rng() -> rand::rngs::StdRng {
    let seed = [0u8; 32];
    rand::rngs::StdRng::from_seed(seed)
}

impl TestSpace {
    pub fn new(name: &str, block_height: u32) -> Self {
        let mut rng = rng();
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

        let mut rng = rng();
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

// ─────────────────────────────────────────────────────────────────────────────
// TestChain - simulated chain state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TestChain {
    pub spaces_tree: SubTree<Sha256Hasher>,
    pub ptrs_tree: SubTree<Sha256Hasher>,
    pub spaces: HashMap<SLabel, TestSpace>,
    pub ptrs: HashMap<Sptr, TestPtr>,
    pub block_height: u32,
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

    pub fn chain_proof(&self) -> ChainProof {
        ChainProof {
            spaces: SpacesSubtree(self.spaces_tree.clone()),
            ptrs: PtrsSubtree(self.ptrs_tree.clone()),
        }
    }

    pub fn increase_time(&mut self, n: u32) {
        self.block_height += n;
    }

    pub fn add_space(&mut self, name: &str) -> TestSpace {
        let space = TestSpace::new(name, self.block_height);
        assert!(!self.spaces.contains_key(&space.label()));

        self.spaces_tree
            .insert(
                space.outpoint_key().into(),
                ValueOrHash::Value(space.spaceout_bytes()),
            )
            .expect("insert space");
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

        let block_hash =
            BlockHash::from_byte_array(rolling_hash::<KeyHash>(spaces_root, ptrs_root));

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

        self.ptrs_tree
            .insert(
                ptr.outpoint_key().into(),
                ValueOrHash::Value(ptr.ptrout_bytes()),
            )
            .expect("insert ptr");

        self.ptrs_tree
            .insert(ptr.sptr().into(), ValueOrHash::Value(ptr.outpoint_bytes()))
            .expect("insert outpoint");
        self.ptrs.insert(ptr.sptr().into(), ptr.clone());
        ptr
    }

    pub fn add_space_with_delegation(&mut self, name: &str) -> TestDelegatedSpace {
        let space = self.add_space(name);
        let ptr = self.add_ptr(space.script_pubkey());

        let registry_sptr_key = RegistrySptrKey::from_sptr::<KeyHash>(ptr.sptr());
        self.ptrs_tree
            .insert(
                registry_sptr_key.into(),
                ValueOrHash::Value(space.label().as_ref().to_vec()),
            )
            .expect("insert registry sptr key");

        TestDelegatedSpace { space, ptr }
    }

    pub fn insert_commitment(
        &mut self,
        ds: &TestDelegatedSpace,
        root: [u8; 32],
    ) -> spaces_ptr::Commitment {
        let prev_finalized = self.rollback_to_finalized_commitment(&ds.space.label());

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
            },
        };

        let commitment_key = CommitmentKey::new::<KeyHash>(&ds.space.label(), root);
        let commitment_bytes = borsh::to_vec(&commitment).expect("valid");

        self.ptrs_tree
            .insert(commitment_key.into(), ValueOrHash::Value(commitment_bytes))
            .expect("insert commitment");
        let registry_key = RegistryKey::from_slabel::<KeyHash>(&ds.space.label());
        self.ptrs_tree
            .update(
                registry_key.into(),
                ValueOrHash::Value(commitment.state_root.to_vec()),
            )
            .expect("insert registry");

        commitment
    }

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

    pub fn rollback_to_finalized_commitment(
        &mut self,
        space: &SLabel,
    ) -> Option<spaces_ptr::Commitment> {
        let commitment = self.get_commitment(space, None)?;
        if commitment.is_finalized(self.block_height) {
            return Some(commitment);
        }

        let registry_key = RegistryKey::from_slabel::<KeyHash>(space);
        let commitment_key = CommitmentKey::new::<KeyHash>(space, commitment.state_root);
        let mut ptrs_tree = self.ptrs_tree.clone();
        ptrs_tree = ptrs_tree.delete(&registry_key.into()).expect("delete");
        ptrs_tree = ptrs_tree.delete(&commitment_key.into()).expect("delete");
        self.ptrs_tree = ptrs_tree;

        let prev_root = commitment.prev_root?;
        let finalized = self.get_commitment(space, Some(prev_root))?;

        self.ptrs_tree
            .update(
                registry_key.into(),
                ValueOrHash::Value(finalized.state_root.to_vec()),
            )
            .expect("update");

        Some(finalized)
    }
}

impl Default for TestChain {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TestHandleTree - operator's off-chain handle tree
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct TestHandleTree {
    pub space: SLabel,
    pub ds: TestDelegatedSpace,
    pub handle_tree: SubTree<Sha256Hasher>,
    pub commitments: Vec<TestCommitmentBundle>,
    pub staged: HashMap<Label, StagedHandle>,
}

impl TestHandle {
    pub fn set_offchain_data(&mut self, seq: u32, data: &[u8]) {
        let mut data = OffchainData {
            seq,
            data: Bytes::new(data.to_vec()),
            signature: Signature([0u8; 64]),
        };
        data.signature = sign_mesage(&data.signing_bytes(), &self.keypair);
        self.offchain_data = Some(data);
    }
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
            !self
                .handle_tree
                .contains(&label_hash)
                .expect("complete tree"),
            "already exists"
        );
        assert!(!self.staged.contains_key(&label), "already staged");

        let (genesis_spk, keypair) = gen_p2tr_spk();
        let handle = TestHandle {
            name: label,
            genesis_spk: genesis_spk.clone(),
            keypair,
            offchain_data: None,
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
        let staged = StagedHandle { handle, signature };

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
                policy_step: libveritas::constants::STEP_ID,
                policy_fold: libveritas::constants::FOLD_ID,
                initial_root,
                final_root,
                rolling_hash: onchain_commitment.rolling_hash,
                kind: libveritas_zk::guest::CommitmentKind::Fold,
            };

            let words = risc0_zkvm::serde::to_vec(&commitment).expect("serialize commitment");
            let journal_bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();

            let receipt_claim =
                ReceiptClaim::ok(libveritas::constants::FOLD_ID, journal_bytes.clone());
            Some(Receipt::new(
                InnerReceipt::Fake(FakeReceipt::new(receipt_claim)),
                journal_bytes,
            ))
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
    pub fn build_message(
        &self,
        chain: &TestChain,
        commitment_idx: usize,
        handle_names: &[&str],
        anchor: &ChainAnchor,
    ) -> Message {
        let tcb = &self.commitments[commitment_idx];

        let spaces_keys: Vec<[u8; 32]> = vec![
            self.ds.space.outpoint_key().into(),
            self.ds.space.space_key().into(),
        ];

        let mut ptrs_keys: Vec<[u8; 32]> =
            vec![self.ds.ptr.outpoint_key().into(), self.ds.ptr.sptr().into()];

        ptrs_keys.push(RegistryKey::from_slabel::<KeyHash>(&self.space).into());
        ptrs_keys.push(CommitmentKey::new::<KeyHash>(&self.space, tcb.root).into());

        let mut handle_keys: Vec<[u8; 32]> = Vec::new();
        let mut handles: Vec<msg::Handle> = Vec::new();

        for &name in handle_names {
            let l = label(name);
            let label_hash = KeyHash::hash(l.as_slabel().as_ref());
            handle_keys.push(label_hash);

            let handle = self.commitments[..=commitment_idx]
                .iter()
                .find_map(|c| c.handles.get(&l))
                .expect("handle must exist in a previous commitment");

            let handle_sptr = Sptr::from_spk::<KeyHash>(handle.genesis_spk.clone());
            ptrs_keys.push(handle_sptr.into());

            handles.push(msg::Handle {
                name: l,
                genesis_spk: handle.genesis_spk.clone(),
                data: None,
                signature: None,
            });
        }

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

    /// Build a temporary certificate message for a staged handle.
    pub fn build_temporary_message(
        &self,
        chain: &TestChain,
        commitment_idx: usize,
        handle_name: &str,
        anchor: &ChainAnchor,
    ) -> Message {
        let tcb = &self.commitments[commitment_idx];
        let staged = self
            .staged
            .get(&label(handle_name))
            .expect("handle must be staged");

        let spaces_keys: Vec<[u8; 32]> = vec![
            self.ds.space.outpoint_key().into(),
            self.ds.space.space_key().into(),
        ];

        let mut ptrs_keys: Vec<[u8; 32]> =
            vec![self.ds.ptr.outpoint_key().into(), self.ds.ptr.sptr().into()];
        ptrs_keys.push(RegistryKey::from_slabel::<KeyHash>(&self.space).into());
        ptrs_keys.push(CommitmentKey::new::<KeyHash>(&self.space, tcb.root).into());

        let handle_sptr = Sptr::from_spk::<KeyHash>(staged.handle.genesis_spk.clone());
        ptrs_keys.push(handle_sptr.into());

        let handle_key = KeyHash::hash(staged.handle.name.as_slabel().as_ref());
        let handle_keys: Vec<[u8; 32]> = vec![handle_key];

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

// ─────────────────────────────────────────────────────────────────────────────
// Veritas builder helper
// ─────────────────────────────────────────────────────────────────────────────

pub fn veritas_from_anchors(anchors: Vec<RootAnchor>) -> Veritas {
    Veritas::new()
        .with_anchors(anchors).expect("valid anchors")
        .with_dev_mode(true)
}
