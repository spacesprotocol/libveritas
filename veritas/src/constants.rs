// Method IDs and ELFs for ZK receipt verification.
//
// These are generated from reproducible (docker) builds of the guest programs.
//
// To update after changing guest programs, run:
//   ./update-elfs.sh

#[rustfmt::skip]
pub const FOLD_ID: [u32; 8] = [3538164873, 3494660837, 1605885420, 2756930862, 1952720968, 91802116, 3635727049, 436347682];
#[rustfmt::skip]
pub const STEP_ID: [u32; 8] = [2719979593, 62333512, 1158600685, 3512173834, 1442236244, 869560259, 553115519, 3467999922];

#[cfg(feature = "elf")]
pub const FOLD_ELF: &[u8] = include_bytes!("../elfs/fold.bin");
#[cfg(feature = "elf")]
pub const STEP_ELF: &[u8] = include_bytes!("../elfs/step.bin");
