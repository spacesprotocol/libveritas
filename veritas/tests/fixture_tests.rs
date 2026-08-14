use libveritas::cert::{NumsSubtree, SpacesSubtree};
#[cfg(feature = "inspect")]
use libveritas::inspect::{ProofPurpose, TreeKind, inspect};
use libveritas::msg::QueryContext;
use libveritas::{ProvableOption, SovereigntyState};
use libveritas_testutil::fixture::{ChainState, FixtureRunner, kitchen_sink};
use spacedb::subtree::ProofType;
use spaces_protocol::sname::NameLike;

#[test]
fn test_space_not_found_in_chain_proof() {
    let mut state = ChainState::new();
    let fixture = kitchen_sink();
    let mut runner = FixtureRunner::new(&mut state, fixture);
    let initial_bundle = runner.build_bundle();
    let mut msg = state.message(vec![initial_bundle]);

    // omit space from chain proof
    msg.chain.spaces = SpacesSubtree(
        msg.chain
            .spaces
            .0
            .prove(&[[0u8; 32]], ProofType::Standard)
            .expect("proving failed"),
    );
    let veritas = state.veritas();
    let ctx = QueryContext::new();
    assert!(
        veritas
            .verify_with_options(&ctx, msg, libveritas::VERIFY_DEV_MODE)
            .is_err()
    );
}

#[test]
fn test_no_delegate_info_provided() {
    let mut state = ChainState::new();
    let fixture = kitchen_sink();

    let mut runner = FixtureRunner::new(&mut state, fixture);
    let initial_bundle = runner.build_bundle();
    let mut msg = state.message(vec![initial_bundle.clone()]);
    msg.chain.nums = NumsSubtree(
        msg.chain
            .nums
            .0
            .prove(&[[64u8; 32]], ProofType::Standard)
            .expect("proving failed"),
    );
    let veritas = state.veritas();
    let ctx = QueryContext::new();
    let res = veritas
        .verify_with_options(&ctx, msg, libveritas::VERIFY_DEV_MODE)
        .expect("valid");

    assert_eq!(res.zones.len(), 1, "expected 1 zones");
    let zone = res.zones.first().unwrap();
    assert!(matches!(zone.delegate, ProvableOption::Unknown));
    assert!(matches!(zone.sovereignty, SovereigntyState::Sovereign));
    assert!(!matches!(zone.commitment, ProvableOption::Exists { .. }));

    // Now create the message without omitting chain proofs
    let msg = state.message(vec![initial_bundle]);
    let mut ctx = QueryContext::new();
    ctx.add_zone(zone.clone());

    let res = veritas
        .verify_with_options(&ctx, msg, libveritas::VERIFY_DEV_MODE)
        .expect("valid");
    assert_eq!(res.zones.len(), 1, "expected 1 zones");
    let zone = res.zones.first().unwrap();
    assert!(matches!(zone.delegate, ProvableOption::Exists { .. }));
    assert!(matches!(zone.sovereignty, SovereigntyState::Sovereign));
    assert!(matches!(zone.commitment, ProvableOption::Empty));
}

#[test]
fn test_kitchen_sink() {
    let mut state = ChainState::new();
    let fixture = kitchen_sink();
    let states = fixture.handle_states();

    let mut runner = FixtureRunner::new(&mut state, fixture);
    runner.run(&mut state);
    let latest_root = runner
        .handles
        .handle_tree
        .compute_root()
        .expect("compute root");

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);

    let ctx = QueryContext::new();
    let veritas = state.veritas();
    let res = veritas
        .verify_with_options(&ctx, msg, libveritas::VERIFY_DEV_MODE)
        .expect("valid");

    assert_eq!(
        states.staged.len(),
        res.zones
            .iter()
            .filter(|z| z.sovereignty == SovereigntyState::Dependent)
            .count()
    );

    let parent_zone = res
        .zones
        .iter()
        .find(|z| z.handle.is_single_label())
        .expect("missing parent");

    let ProvableOption::Exists { value: commitment } = &parent_zone.commitment else {
        panic!("commit should exist");
    };

    assert!(commitment.receipt_hash.is_some());
    assert_eq!(commitment.onchain.state_root, latest_root);

    for zone in res.zones {
        if zone.handle.is_single_label() {
            continue;
        }
        let expected = states
            .sovereignty(&zone.handle.subspace().unwrap().to_string())
            .expect("handle exists");

        assert_eq!(expected, zone.sovereignty);
    }
}

#[cfg(feature = "inspect")]
#[test]
fn test_inspect_proof_shape() {
    let mut state = ChainState::new();
    let fixture = kitchen_sink();
    let mut runner = FixtureRunner::new(&mut state, fixture);
    runner.run(&mut state);

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);
    let veritas = state.veritas();

    let report = inspect(&veritas, &msg).expect("inspect");

    assert_eq!(report.anchor.block_height, msg.chain.anchor.height);
    assert!(!report.zones.is_empty(), "expected zones");

    // First zone must be the parent space.
    let parent = &report.zones[0];
    assert!(parent.parent.is_none());
    assert!(parent.handle.starts_with('@'));
    let parent_path_count = parent.paths.len();
    assert!(parent_path_count > 0, "parent should have paths");

    // Parent must have a spaces_root path.
    assert!(
        parent
            .paths
            .iter()
            .any(|p| matches!(p.tree, TreeKind::SpacesRoot)
                && matches!(p.purpose, ProofPurpose::SpaceUtxo))
    );

    // Parent zone carries its own tip commitment.
    assert!(
        parent
            .paths
            .iter()
            .any(|p| matches!(p.purpose, ProofPurpose::Commitment)),
        "parent should have a tip commitment path"
    );

    // At least one handle zone.
    let handle_zones: Vec<_> = report.zones.iter().filter(|z| z.parent.is_some()).collect();
    assert!(!handle_zones.is_empty(), "expected handle zones");
    let h = handle_zones[0];

    // A handle inherits the parent's identity (space ownership) path...
    assert!(
        h.paths
            .iter()
            .any(|p| matches!(p.purpose, ProofPurpose::SpaceUtxo)),
        "handle should inherit the parent space ownership path"
    );
    // ...carries its own epoch commitment linking to the handles root...
    assert!(
        h.paths
            .iter()
            .any(|p| matches!(p.purpose, ProofPurpose::Commitment)
                && matches!(p.provides_root, Some(TreeKind::HandlesRoot))),
        "handle should have an epoch commitment providing the handles root"
    );
    // ...and its own handles-tree inclusion/exclusion path.
    assert!(
        h.paths
            .iter()
            .any(|p| matches!(p.tree, TreeKind::HandlesRoot))
    );

    // Parent is on-chain → Sovereign, and its bundle carried a ZK receipt
    // (kitchen_sink commits a pending epoch), so the receipt block decodes.
    assert!(matches!(
        parent.sovereignty,
        Some(SovereigntyState::Sovereign)
    ));
    let receipt = parent.receipt.as_ref().expect("parent receipt block");
    assert!(
        receipt.policy_ok,
        "receipt policy IDs should match this build"
    );
    assert!(matches!(receipt.kind.as_str(), "fold" | "step"));

    // Every handle zone reports a sovereignty, and kitchen_sink stages
    // temporary (Dependent) handles.
    assert!(handle_zones.iter().all(|z| z.sovereignty.is_some()));
    assert!(
        handle_zones
            .iter()
            .any(|z| matches!(z.sovereignty, Some(SovereigntyState::Dependent))),
        "expected at least one dependent (temporary) handle"
    );

    // Every path resolves to a concrete state (no field left unset).
    for z in &report.zones {
        for p in &z.paths {
            use libveritas::inspect::Resolution;
            assert!(matches!(
                p.resolution,
                Resolution::Included | Resolution::ProvablyExcluded | Resolution::Incomplete
            ));
        }
    }

    // Sibling hashes must be 32 bytes.
    for z in &report.zones {
        for p in &z.paths {
            for s in &p.steps {
                assert_eq!(s.sibling_hash.len(), 32);
            }
        }
    }

    // The JSON shape should round-trip through serde_json without panicking.
    let json = serde_json::to_string(&report).expect("serialize");
    assert!(json.contains("\"spaces_root\""));
    assert!(json.contains("\"steps\""));
}

// Records whose signature does not verify are omitted from the verified
// message, and inspect is the channel that surfaces that omission (a synthetic
// record injected into the set would break the "everything here is signed"
// invariant and be spoofable, so the status lives in the report instead).
#[cfg(feature = "inspect")]
#[test]
fn inspect_flags_invalid_records() {
    use libveritas::inspect::{SigStatus, inspect};
    use libveritas::msg::UnsignedRecordSet;
    use spaces_protocol::sname::SName;

    let mut state = ChainState::new();
    let fixture = kitchen_sink();
    let mut runner = FixtureRunner::new(&mut state, fixture);
    runner.run(&mut state);

    let mut bundle = runner.build_bundle();

    // Owner records on the parent space zone with the correct canonical name
    // but a garbage signature, so it cannot verify against the space key. (A
    // fresh keypair would be unreliable here: testutil's keygen is
    // deterministic and can collide with the fixture's own space key.)
    let canonical = SName::from_space(&bundle.subject);
    let unsigned = UnsignedRecordSet {
        handle: canonical.clone(),
        canonical: canonical.clone(),
        flags: sip7::SIG_PRIMARY_ZONE,
        records: sip7::RecordSet::pack(vec![sip7::Record::txt("name", &["nope"])])
            .expect("pack records"),
        delegate: false,
    };
    bundle.records = Some(unsigned.pack_sig(vec![0xABu8; 64]));

    let msg = state.message(vec![bundle]);
    let veritas = state.veritas();
    let report = inspect(&veritas, &msg).expect("inspect");

    // Parent owner records: present but flagged Invalid (i.e. omitted).
    let parent = report
        .zones
        .iter()
        .find(|z| z.handle == canonical.to_string())
        .expect("parent zone");
    assert_eq!(
        parent.records.owner.as_ref().map(|r| r.signature),
        Some(SigStatus::Invalid),
        "inspect should flag records with a bad signature as Invalid"
    );

    // The fixture's genuinely owner-signed handle records are flagged Valid.
    assert!(
        report
            .zones
            .iter()
            .filter(|z| z.parent.is_some())
            .filter_map(|z| z.records.owner.as_ref())
            .any(|r| r.signature == SigStatus::Valid),
        "valid handle records should be flagged Valid"
    );
}
