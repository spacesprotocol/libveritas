use spacedb::subtree::{ProofType};
use libveritas::cert::{PtrsSubtree, SpacesSubtree};
use libveritas::{ProvableOption, SovereigntyState};
use libveritas::msg::{QueryContext};
use libveritas::sname::NameLike;
use libveritas_testutil::fixture::{kitchen_sink, ChainState, FixtureRunner};

#[test]
fn test_space_not_found_in_chain_proof() {
    let mut state = ChainState::new();
    let fixture = kitchen_sink();
    let mut runner = FixtureRunner::new(&mut state, fixture);
    let initial_bundle = runner.build_bundle();
    let mut msg = state.message(vec![initial_bundle]);

    // omit space from chain proof
    msg.chain.spaces = SpacesSubtree(
        msg.chain.spaces.0
        .prove(&[[0u8;32]], ProofType::Standard).expect("proving failed")
    );
    let veritas = state.veritas();
    let ctx = QueryContext::new();
    assert!(veritas.verify_message(&ctx, msg).is_err());
}

#[test]
fn test_no_delegate_info_provided() {
    let mut state = ChainState::new();
    let fixture = kitchen_sink();

    let mut runner = FixtureRunner::new(&mut state, fixture);
    let initial_bundle = runner.build_bundle();
    let mut msg = state.message(vec![initial_bundle.clone()]);
    msg.chain.ptrs = PtrsSubtree(
        msg.chain.ptrs.0
        .prove(&[[64u8;32]], ProofType::Standard).expect("proving failed")
    );
    let veritas = state.veritas();
    let ctx = QueryContext::new();
    let res = veritas.verify_message(&ctx, msg).expect("valid");

    assert_eq!(res.zones.len(), 1, "expected 1 zones");
    let zone = res.zones.first().unwrap();
    assert!(matches!(zone.delegate, ProvableOption::Unknown));
    assert!(matches!(zone.sovereignty,  SovereigntyState::Sovereign));
    assert!(!matches!(zone.commitment,  ProvableOption::Exists {..}));

    // Now create the message without omitting chain proofs
    let msg = state.message(vec![initial_bundle]);
    let mut ctx = QueryContext::new();
    ctx.add_zone(zone.clone());

    let res = veritas.verify_message(&ctx, msg).expect("valid");
    assert_eq!(res.zones.len(), 1, "expected 1 zones");
    let zone = res.zones.first().unwrap();
    assert!(matches!(zone.delegate, ProvableOption::Exists { .. }));
    assert!(matches!(zone.sovereignty,  SovereigntyState::Sovereign));
    assert!(matches!(zone.commitment,  ProvableOption::Empty));
}


#[test]
fn test_kitchen_sink() {
    let mut state = ChainState::new();
    let fixture = kitchen_sink();
    let states = fixture.handle_states();

    let mut runner = FixtureRunner::new(&mut state, fixture);
    runner.run(&mut state);
    let latest_root = runner.handles.handle_tree.compute_root().expect("compute root");

    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);

    let ctx = QueryContext::new();
    let veritas = state.veritas();
    let res = veritas.verify_message(&ctx, msg).expect("valid");

    assert_eq!(
        states.staged.len(),
        res.zones.iter().filter(|z| z.sovereignty == SovereigntyState::Dependent).count()
    );

    let parent_zone = res.zones.iter().find(|z| z.handle.is_single_label())
        .expect("missing parent");

    let ProvableOption::Exists { value : commitment } = &parent_zone.commitment else {
        panic!("commit should exist");
    };

    assert!(commitment.receipt_hash.is_some());
    assert_eq!(commitment.onchain.state_root, latest_root);

    for zone in res.zones {
        if zone.handle.is_single_label() {
            continue;
        }
        let expected = states.sovereignty(
            &zone.handle.subspace().unwrap().to_string()
        ).expect("handle exists");

        assert_eq!(expected, zone.sovereignty);
    }
}
