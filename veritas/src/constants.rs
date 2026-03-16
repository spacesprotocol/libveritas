// Method IDs and ELFs for ZK receipt verification.
//
// These are generated from reproducible (docker) builds of the guest programs.
//
// To update after changing guest programs, run:
//   ./update-elfs.sh

pub const FOLD_ID: [u32; 8] = [2384190005, 1383356962, 1611954056, 3955398799, 1165431028, 3158662382, 3885746088, 2649839055];
pub const STEP_ID: [u32; 8] = [2901559266, 2330516055, 3423470327, 264593649, 3871226852, 227032398, 197637259, 2624717186];

#[cfg(feature = "elf")]
pub const FOLD_ELF: &[u8] = include_bytes!("../elfs/fold.bin");
#[cfg(feature = "elf")]
pub const STEP_ELF: &[u8] = include_bytes!("../elfs/step.bin");
