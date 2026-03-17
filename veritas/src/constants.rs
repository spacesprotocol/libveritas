// Method IDs and ELFs for ZK receipt verification.
//
// These are generated from reproducible (docker) builds of the guest programs.
//
// To update after changing guest programs, run:
//   ./update-elfs.sh

pub const FOLD_ID: [u32; 8] = [2000209242, 4137684889, 1470876129, 3958521700, 733737245, 2578981204, 1794195557, 1129418281];
pub const STEP_ID: [u32; 8] = [357502740, 3749433395, 3687934168, 821678710, 1887084606, 1735114615, 3360017477, 2259127679];

#[cfg(feature = "elf")]
pub const FOLD_ELF: &[u8] = include_bytes!("../elfs/fold.bin");
#[cfg(feature = "elf")]
pub const STEP_ELF: &[u8] = include_bytes!("../elfs/step.bin");
