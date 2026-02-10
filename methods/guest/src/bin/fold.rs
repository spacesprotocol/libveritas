use risc0_zkvm::{guest::env, serde, sha::{Impl, Sha256}};

use libveritas_zk::guest::{Commitment, CommitmentKind};

fn main() {
    let (c1, c2): (Commitment, Commitment) = env::read();

    assert_eq!(c1.final_root, c2.initial_root, "roots must match");
    assert_eq!(c1.space, c2.space, "space must match");
    assert_eq!(c1.policy_step, c2.policy_step, "policy step must match");
    assert_eq!(c1.policy_fold, c2.policy_fold, "policy fold must match");

    match c1.kind {
        CommitmentKind::Step => env::verify(c1.policy_step, &serde::to_vec(&c1).unwrap()).unwrap(),
        CommitmentKind::Fold => env::verify(c1.policy_fold, &serde::to_vec(&c1).unwrap()).unwrap(),
    }
    match c2.kind {
        CommitmentKind::Step => env::verify(c2.policy_step, &serde::to_vec(&c2).unwrap()).unwrap(),
        CommitmentKind::Fold => env::verify(c2.policy_fold, &serde::to_vec(&c2).unwrap()).unwrap(),
    }

    let mut hash_msg = [0u8;64];
    hash_msg[..32].copy_from_slice(&c1.rolling_hash);
    hash_msg[32..].copy_from_slice(&c2.final_root);
    let rolling_hash = Impl::hash_bytes(&hash_msg).as_bytes().try_into().expect("works");

    env::commit(&Commitment {
        space: c1.space,
        initial_root: c1.initial_root,
        final_root: c2.final_root,
        rolling_hash,
        kind: CommitmentKind::Fold,
        policy_step: c1.policy_step,
        policy_fold: c1.policy_fold,
    });
}
