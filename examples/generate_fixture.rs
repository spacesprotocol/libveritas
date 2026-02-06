/// Generates test fixture files for the examples.
///
/// Outputs:
///   examples/fixture/anchors.json   - JSON array of RootAnchors
///   examples/fixture/message.bin    - borsh-encoded Message

use libveritas::msg::QueryContext;
use libveritas_testutil::fixture::{ChainState, FixtureRunner, single_commit_finalized};
use std::fs;

fn main() {
    let dir = std::path::Path::new("examples/fixture");
    fs::create_dir_all(dir).unwrap();

    // Build a "single commit finalized" scenario:
    // space @sovereign with handles alice, bob — both sovereign
    let mut state = ChainState::new();
    let fixture = single_commit_finalized();
    let mut runner = FixtureRunner::new(&mut state, fixture);
    runner.run(&mut state);

    // Snapshot the anchor after all state changes
    state.anchors.push(state.chain.current_root_anchor());

    // Build the message using the current chain state
    let bundle = runner.build_bundle();
    let msg = state.message(vec![bundle]);

    // Anchors as JSON (newest first, as Veritas expects)
    let mut anchors = state.anchors.clone();
    anchors.reverse();
    let anchors_json = serde_json::to_string_pretty(&anchors).unwrap();
    fs::write(dir.join("anchors.json"), &anchors_json).unwrap();
    println!("wrote anchors.json ({} anchors)", anchors.len());

    // Message as borsh
    let msg_bytes = borsh::to_vec(&msg).unwrap();
    fs::write(dir.join("message.bin"), &msg_bytes).unwrap();
    println!("wrote message.bin ({} bytes)", msg_bytes.len());

    // Native verify to confirm the fixture is valid
    let veritas = state.veritas();
    let ctx = QueryContext::new();
    let result = veritas.verify_message(&ctx, msg).unwrap();
    println!("\nnative verify OK: {} zones", result.zones.len());
    for z in &result.zones {
        println!("  {} -> {}", z.handle, z.sovereignty);
    }
}
