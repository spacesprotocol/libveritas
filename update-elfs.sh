#!/bin/bash

# Builds guest programs reproducibly using Docker and updates
# the baked ELFs and image IDs in the veritas crate.
#
# Requirements: cargo-risczero 3.0.5, r0vm 3.0.5, Docker

set -eo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ELFS_DIR="${SCRIPT_DIR}/veritas/elfs"
CONSTANTS_FILE="${SCRIPT_DIR}/veritas/src/constants.rs"
GUEST_DIR="${SCRIPT_DIR}/methods/guest"
DOCKER_OUT="${GUEST_DIR}/target/riscv32im-risc0-zkvm-elf/docker"

# Convert a 64-char hex string to a [u32; 8] Rust array (little-endian)
hex_to_u32_array() {
    local hex=$1
    local result="["
    for i in 0 8 16 24 32 40 48 56; do
        # Extract 8 hex chars (4 bytes)
        local chunk=${hex:$i:8}
        # Swap to little-endian: abcdefgh -> ghefcdab
        local le="${chunk:6:2}${chunk:4:2}${chunk:2:2}${chunk:0:2}"
        # Convert to decimal
        local dec=$((16#${le}))
        if [ $i -gt 0 ]; then result+=", "; fi
        result+="${dec}"
    done
    result+="]"
    echo "$result"
}

mkdir -p "${ELFS_DIR}"

echo "Building guest programs with Docker..."
cargo risczero build --manifest-path "${GUEST_DIR}/Cargo.toml"

echo "Copying ELFs..."
cp "${DOCKER_OUT}/fold.bin" "${ELFS_DIR}/"
cp "${DOCKER_OUT}/step.bin" "${ELFS_DIR}/"

echo "Computing image IDs..."
FOLD_HEX=$(r0vm --id --elf "${ELFS_DIR}/fold.bin")
STEP_HEX=$(r0vm --id --elf "${ELFS_DIR}/step.bin")

echo "FOLD image ID: ${FOLD_HEX}"
echo "STEP image ID: ${STEP_HEX}"

FOLD_U32=$(hex_to_u32_array "${FOLD_HEX}")
STEP_U32=$(hex_to_u32_array "${STEP_HEX}")

echo "Updating constants.rs..."
cat > "${CONSTANTS_FILE}" << EOF
// Method IDs and ELFs for ZK receipt verification.
//
// These are generated from reproducible (docker) builds of the guest programs.
//
// To update after changing guest programs, run:
//   ./update-elfs.sh

pub const FOLD_ID: [u32; 8] = ${FOLD_U32};
pub const STEP_ID: [u32; 8] = ${STEP_U32};

#[cfg(feature = "elf")]
pub const FOLD_ELF: &[u8] = include_bytes!("../elfs/fold.bin");
#[cfg(feature = "elf")]
pub const STEP_ELF: &[u8] = include_bytes!("../elfs/step.bin");
EOF

echo "Done."
echo "FOLD_ID: ${FOLD_U32}"
echo "STEP_ID: ${STEP_U32}"
