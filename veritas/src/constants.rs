// Method IDs and ELFs for ZK receipt verification.
//
// These are generated from reproducible (docker) builds of the guest programs.
//
// To update after changing guest programs, run:
//   ./update-elfs.sh

pub const FOLD_ID: [u32; 8] = [524008615, 1027686441, 358720433, 745629775, 1729316702, 1483879221, 1162362469, 1835986606];
pub const STEP_ID: [u32; 8] = [664565856, 314861063, 3530579611, 1001594314, 3512226603, 1901436919, 2995000795, 1715160485];

#[cfg(feature = "elf")]
pub const FOLD_ELF: &[u8] = include_bytes!("../elfs/fold.bin");
#[cfg(feature = "elf")]
pub const STEP_ELF: &[u8] = include_bytes!("../elfs/step.bin");
