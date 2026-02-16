use spacedb::subtree::SubTree;
use spaces_ptr::constants::COMMITMENT_FINALITY_INTERVAL;
use spaces_ptr::RootAnchor;
use libveritas::{msg, SovereigntyState, Veritas};
use libveritas::cert::{HandleSubtree, PtrsSubtree, SpacesSubtree};
use libveritas::msg::{Bundle, ChainProof};
use crate::{TestChain, TestDelegatedSpace, TestHandleTree};

#[derive(Clone,Debug)]
pub enum Step {
    Stage(&'static [&'static str]),
    Commit,
    Finalize,
}

#[derive(Clone,Debug)]
pub struct Fixture {
    pub name: &'static str,
    pub steps: Vec<Step>,
}

pub struct HandleStates {
    /// Handles in each commitment, indexed by commitment number
    pub commits: Vec<Vec<&'static str>>,
    /// Handles staged but not yet committed
    pub staged: Vec<&'static str>,
    /// Number of finalized commitments
    pub finalized_count: usize,
}

impl HandleStates {
    /// All committed handles (any commitment)
    pub fn all_committed(&self) -> Vec<&'static str> {
        self.commits.iter().flatten().copied().collect()
    }

    /// Handles in a specific commitment
    pub fn in_commit(&self, index: usize) -> &[&'static str] {
        self.commits.get(index).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Is this handle committed (in any commitment)?
    pub fn is_committed(&self, handle: &str) -> bool {
        self.commits.iter().flatten().any(|&h| h == handle)
    }

    /// Is this handle staged (not yet committed)?
    pub fn is_staged(&self, handle: &str) -> bool {
        self.staged.contains(&handle)
    }

    /// Which commitment contains this handle? None if staged/not found.
    pub fn commit_index(&self, handle: &str) -> Option<usize> {
        self.commits.iter().position(|c| c.contains(&handle))
    }

    /// Latest commitment index (None if no commits)
    pub fn latest_commit(&self) -> Option<&Vec<&str>> {
        self.commits.last()
    }

    pub fn pending_commit(&self) -> Option<&Vec<&str>> {
        if !self.has_pending_commit() {
            return None;
        }

        self.latest_commit()
    }

    /// Total number of commitments
    pub fn commit_count(&self) -> usize {
        self.commits.len()
    }

    /// Is there a pending (non-finalized) commitment?
    pub fn has_pending_commit(&self) -> bool {
        self.commits.len() > self.finalized_count
    }

    /// Does this handle need a receipt when verified?
    /// (Handles in commitment > 0 need receipt verification)
    pub fn needs_receipt(&self, handle: &str) -> bool {
        self.commit_index(handle).map(|i| i > 0).unwrap_or(false)
    }

    /// Expected sovereignty for a committed handle
    pub fn sovereignty(&self, handle: &str) -> Option<SovereigntyState> {
        if self.staged.iter().find(|&&s| s == handle).is_some() {
            return Some(SovereigntyState::Dependent)
        }
        
        let commit_idx = self.commit_index(handle)?;
        if commit_idx < self.finalized_count {
            Some(SovereigntyState::Sovereign)
        } else {
            Some(SovereigntyState::Pending)
        }
    }
}

impl Fixture {
    pub fn new(name: &'static str) -> Self {
        Self { name, steps: vec![] }
    }

    pub fn stage(mut self, handles: &'static [&'static str]) -> Self {
        self.steps.push(Step::Stage(handles));
        self
    }

    pub fn commit(mut self) -> Self {
        self.steps.push(Step::Commit);
        self
    }

    pub fn finalize(mut self) -> Self {
        self.steps.push(Step::Finalize);
        self
    }

    pub fn then(mut self, other: Fixture) -> Self {
        self.steps.extend(other.steps);
        self
    }

    /// Analyze steps to determine handle states
    pub fn handle_states(&self) -> HandleStates {
        let mut commits: Vec<Vec<&'static str>> = vec![];
        let mut staged: Vec<&'static str> = vec![];
        let mut finalized_count: usize = 0;

        for step in &self.steps {
            match step {
                Step::Stage(handles) => {
                    staged.extend(*handles);
                }
                Step::Commit => {
                    commits.push(std::mem::take(&mut staged));
                }
                Step::Finalize => {
                    finalized_count += 1;
                }
            }
        }

        HandleStates { commits, staged, finalized_count }
    }
}

#[derive(Clone)]
pub struct ChainState {
    pub chain: TestChain,
    pub anchors: Vec<RootAnchor>,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            chain: TestChain::new(),
            anchors: vec![],
        }
    }
    
    pub fn veritas(&self) -> Veritas {
        let mut anchors = self.anchors.clone();
        if anchors.is_empty() {
            anchors.push(self.chain.current_root_anchor());
        }
        anchors.reverse();
        Veritas::new()
            .with_anchors(anchors).expect("valid anchors")
            .with_dev_mode(true)
    }

    pub fn message(&self, bundles: Vec<Bundle>) -> msg::Message {
        msg::Message {
            anchor: self.chain.current_root_anchor().block,
            chain: ChainProof {
                spaces: SpacesSubtree(self.chain.spaces_tree.clone()),
                ptrs: PtrsSubtree(self.chain.ptrs_tree.clone()),
            },
            spaces: bundles,
        }
    }
}

#[derive(Clone)]
pub struct FixtureRunner{
    pub fixture: Fixture,
    pub step: std::vec::IntoIter<Step>,
    pub space: TestDelegatedSpace,
    pub handles: TestHandleTree,
    pub anchors: Vec<RootAnchor>,
}

impl FixtureRunner {
    pub fn new(state: &mut ChainState, fixture: Fixture) -> Self {
        let space = state.chain.add_space_with_delegation(fixture.name);
        let handles = TestHandleTree::new(&space);
        Self {
            step: fixture.steps.clone().into_iter(),
            space,
            fixture,
            anchors: vec![],
            handles,
        }
    }

    pub fn build_bundle(&mut self) -> msg::Bundle {
        let mut bundle = msg::Bundle {
            space: self.space.space.label(),
            receipt: None,
            epochs: vec![],
            offchain_data: None,
            delegate_offchain_data: None,
        };

        for c in &mut self.handles.commitments {
            bundle.receipt = c.receipt.clone();
            let mut epoch = msg::Epoch {
                tree: HandleSubtree(c.handle_tree.clone()),
                handles: vec![],
            };
            for (_, handle) in &mut c.handles {
                // Add some off-chain data
                handle.set_offchain_data(
                    0,
                    handle.name.as_slabel().clone().as_ref()
                );

                epoch.handles.push(msg::Handle {
                    name: handle.name.clone(),
                    genesis_spk: handle.genesis_spk.clone(),
                    data: handle.offchain_data.clone(),
                    signature: None,
                })
            }
            bundle.epochs.push(epoch);
        }

        let mut empty_epoch = msg::Epoch {
            tree:  HandleSubtree(SubTree::empty()),
            handles: vec![],
        };
        let staging = bundle.epochs.last_mut().unwrap_or(&mut empty_epoch);

        for (_, staged) in &mut self.handles.staged {
            // add some off-chain data
            staged.handle.set_offchain_data(
                0,
                staged.handle.name.as_slabel().clone().as_ref()
            );
            staging.handles.push(msg::Handle {
                name: staged.handle.name.clone(),
                genesis_spk: staged.handle.genesis_spk.clone(),
                data: staged.handle.offchain_data.clone(),
                signature: Some(staged.signature),
            })
        }
        if !empty_epoch.handles.is_empty() {
            bundle.epochs.push(empty_epoch);
        }
        bundle
    }

    pub fn run_next(&mut self, state: &mut ChainState) -> Option<Step> {
        let step = self.step.next()?;
        match &step {
            Step::Stage(stage) => {
                for &name in *stage {
                    self.handles.add_handle(name);
                }
            }
            Step::Commit => {
                self.handles.commit(&mut state.chain);
                state.anchors.push(state.chain.current_root_anchor())
            }
            Step::Finalize => {
                state.chain.increase_time(COMMITMENT_FINALITY_INTERVAL + 1);
            }
        }
        Some(step)
    }

    pub fn run(&mut self, state: &mut ChainState) {
        while  self.run_next(state).is_some() {}
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FIXTURES
// ═══════════════════════════════════════════════════════════════════════════

/// No commitments, just staged handles. Temp certs need no exclusion proof.
pub fn staged_only() -> Fixture {
    Fixture::new("@staged")
        .stage(&["alice", "bob"])
}

/// Single commitment, not yet finalized. Handles are Pending.
pub fn single_commit_pending() -> Fixture {
    Fixture::new("@pending")
        .stage(&["alice", "bob"])
        .commit()
}

/// Single commitment, finalized. Handles are Sovereign. No receipt needed.
pub fn single_commit_finalized() -> Fixture {
    Fixture::new("@sovereign")
        .stage(&["alice", "bob"])
        .commit()
        .finalize()
}

/// Two commitments: first finalized, second pending. Receipt required.
pub fn two_commits_second_pending() -> Fixture {
    Fixture::new("@two-pending")
        .stage(&["alice", "bob"])
        .commit()
        .finalize()
        .stage(&["charlie"])
        .commit()
}

/// Two commitments, both finalized.
pub fn two_commits_both_finalized() -> Fixture {
    Fixture::new("@two-finalized")
        .stage(&["alice", "bob"])
        .commit()
        .finalize()
        .stage(&["charlie"])
        .commit()
        .finalize()
}

/// Finalized commit + new staged handle (for temp cert with exclusion proof).
pub fn finalized_with_staged() -> Fixture {
    Fixture::new("@finalized-staged")
        .stage(&["alice"])
        .commit()
        .finalize()
        .stage(&["bob"])
}

/// Kitchen sink: multiple commitments, mixed finality, plus staged handles.
/// - Commit 0 (finalized): alice, bob
/// - Commit 1 (finalized): charlie, dave
/// - Commit 2 (pending):   eve, frank
/// - Staged (no commit):   grace, heidi
pub fn kitchen_sink() -> Fixture {
    Fixture::new("@kitchensink")
        .stage(&["alice", "bob"])
        .commit()
        .finalize()
        .stage(&["charlie", "dave"])
        .commit()
        .finalize()
        .stage(&["eve", "frank"])
        .commit()
        .stage(&["grace", "heidi"])
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_states_staged_only() {
        let states = staged_only().handle_states();

        assert_eq!(states.commits.len(), 0);
        assert_eq!(states.staged, vec!["alice", "bob"]);
        assert!(states.is_staged("alice"));
        assert!(!states.is_committed("alice"));
        assert!(!states.has_pending_commit());
    }

    #[test]
    fn test_handle_states_single_commit_finalized() {
        let states = single_commit_finalized().handle_states();

        assert_eq!(states.commits.len(), 1);
        assert_eq!(states.in_commit(0), &["alice", "bob"]);
        assert!(states.staged.is_empty());
        assert!(states.is_committed("alice"));
        assert_eq!(states.commit_index("alice"), Some(0));
        assert!(!states.has_pending_commit());
        assert_eq!(states.sovereignty("alice"), Some(SovereigntyState::Sovereign));
    }

    #[test]
    fn test_handle_states_two_commits_second_pending() {
        let states = two_commits_second_pending().handle_states();

        assert_eq!(states.commits.len(), 2);
        assert_eq!(states.finalized_count, 1);
        assert!(states.has_pending_commit());

        // alice is in finalized commit 0
        assert_eq!(states.commit_index("alice"), Some(0));
        assert_eq!(states.sovereignty("alice"), Some(SovereigntyState::Sovereign));
        assert!(!states.needs_receipt("alice"));

        // charlie is in pending commit 1
        assert_eq!(states.commit_index("charlie"), Some(1));
        assert_eq!(states.sovereignty("charlie"), Some(SovereigntyState::Pending));
        assert!(states.needs_receipt("charlie"));
    }

    #[test]
    fn test_handle_states_kitchen_sink() {
        let states = kitchen_sink().handle_states();

        assert_eq!(states.commits.len(), 3);
        assert_eq!(states.finalized_count, 2);
        assert!(states.has_pending_commit());

        // Commit 0 (finalized): alice, bob
        assert_eq!(states.in_commit(0), &["alice", "bob"]);
        assert_eq!(states.sovereignty("alice"), Some(SovereigntyState::Sovereign));
        assert!(!states.needs_receipt("alice"));

        // Commit 1 (finalized): charlie, dave
        assert_eq!(states.in_commit(1), &["charlie", "dave"]);
        assert_eq!(states.sovereignty("charlie"), Some(SovereigntyState::Sovereign));
        assert!(states.needs_receipt("charlie")); // commit > 0

        // Commit 2 (pending): eve, frank
        assert_eq!(states.in_commit(2), &["eve", "frank"]);
        assert_eq!(states.sovereignty("eve"), Some(SovereigntyState::Pending));
        assert!(states.needs_receipt("eve"));

        // Staged: grace, heidi
        assert_eq!(states.staged, vec!["grace", "heidi"]);
        assert!(states.is_staged("grace"));
        assert!(!states.is_committed("grace"));
        assert_eq!(states.sovereignty("grace"), None);
    }
}
