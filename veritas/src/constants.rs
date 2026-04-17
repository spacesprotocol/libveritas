// Method IDs and ELFs for ZK receipt verification.
//
// These are generated from reproducible (docker) builds of the guest programs.
//
// To update after changing guest programs, run:
//   ./update-elfs.sh

#[rustfmt::skip]
pub const FOLD_ID: [u32; 8] = [1625847226, 850230740, 496504626, 3639083801, 2684129074, 2250774282, 3408390548, 2223737758];
#[rustfmt::skip]
pub const STEP_ID: [u32; 8] = [4183517563, 124613694, 2850288930, 1547396554, 892696396, 2291296768, 2705493164, 2273870659];

#[cfg(feature = "elf")]
pub const FOLD_ELF: &[u8] = include_bytes!("../elfs/fold.bin");
#[cfg(feature = "elf")]
pub const STEP_ELF: &[u8] = include_bytes!("../elfs/step.bin");
