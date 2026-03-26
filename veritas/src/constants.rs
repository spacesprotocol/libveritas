// Method IDs and ELFs for ZK receipt verification.
//
// These are generated from reproducible (docker) builds of the guest programs.
//
// To update after changing guest programs, run:
//   ./update-elfs.sh

pub const FOLD_ID: [u32; 8] = [2137388158, 139300334, 1332819426, 2098328572, 332487338, 683648994, 3447504890, 2081197365];
pub const STEP_ID: [u32; 8] = [3974921952, 1965078643, 1566874199, 1666253710, 1661334525, 217836664, 127468841, 245176993];

#[cfg(feature = "elf")]
pub const FOLD_ELF: &[u8] = include_bytes!("../elfs/fold.bin");
#[cfg(feature = "elf")]
pub const STEP_ELF: &[u8] = include_bytes!("../elfs/step.bin");
