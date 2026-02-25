// Method IDs for ZK receipt verification.
//
// Hardcoded here to avoid relying on methods crate since it needs risc0 toolchain.
//
// To update after changing guest programs:
//   1. Build the methods crate: cargo build -p libveritas_methods
//   2. Copy FOLD_ID and STEP_ID from the generated file:
//      target/debug/build/libveritas_methods-*/out/methods.rs

pub const FOLD_ID: [u32; 8] = [4057896122, 3448775116, 3466485410, 3036163001, 1103873946, 3889477734, 4278389213, 67817676];
pub const STEP_ID: [u32; 8] = [504298350, 2690744795, 148952875, 2556916216, 3739630024, 299707457, 1792780313, 2285557624];
