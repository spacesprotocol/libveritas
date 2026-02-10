use std::sync::{Arc, RwLock};

use libveritas::msg::{Message, QueryContext};
use libveritas::sname::SName;
use libveritas::Zone;
use spaces_ptr::RootAnchor;
use std::str::FromStr;

uniffi::setup_scaffolding!();

// -- Errors --

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VeritasError {
    #[error("{message}")]
    InvalidInput { message: String },
    #[error("{message}")]
    VerificationFailed { message: String },
}

// -- Enums --

#[derive(uniffi::Enum)]
pub enum VeritasDelegateState {
    Exists { script_pubkey: Vec<u8>, data: Option<Vec<u8>>, offchain_data: Option<VeritasOffchainData> },
    Empty,
    Unknown,
}

#[derive(uniffi::Enum)]
pub enum VeritasCommitmentState {
    Exists {
        state_root: Vec<u8>,
        prev_root: Option<Vec<u8>>,
        rolling_hash: Vec<u8>,
        block_height: u32,
        receipt_hash: Option<Vec<u8>>,
    },
    Empty,
    Unknown,
}

// -- Records --

#[derive(uniffi::Record)]
pub struct VeritasOffchainData {
    pub seq: u32,
    pub data: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct VeritasCertificate {
    pub subject: String,
    pub cert_type: String,
    pub bytes: Vec<u8>,
}

// -- Conversions --

fn cert_to_record(c: &libveritas::cert::Certificate) -> VeritasCertificate {
    let cert_type = if c.is_temporary() {
        "temporary"
    } else if c.is_leaf() {
        "final"
    } else {
        "root"
    };
    VeritasCertificate {
        subject: c.subject.to_string(),
        cert_type: cert_type.to_string(),
        bytes: c.to_bytes(),
    }
}

// -- Objects --

#[derive(uniffi::Object)]
pub struct VeritasZone {
    inner: Zone,
}

#[uniffi::export]
impl VeritasZone {
    pub fn anchor(&self) -> u32 {
        self.inner.anchor
    }

    pub fn sovereignty(&self) -> String {
        self.inner.sovereignty.to_string()
    }

    pub fn handle(&self) -> String {
        self.inner.handle.to_string()
    }

    pub fn script_pubkey(&self) -> Vec<u8> {
        self.inner.script_pubkey.as_bytes().to_vec()
    }

    pub fn data(&self) -> Option<Vec<u8>> {
        self.inner.data.as_ref().map(|d| d.as_slice().to_vec())
    }

    pub fn offchain_data(&self) -> Option<VeritasOffchainData> {
        self.inner.offchain_data.as_ref().map(|od| VeritasOffchainData {
            seq: od.seq,
            data: od.data.clone(),
        })
    }

    pub fn delegate(&self) -> VeritasDelegateState {
        match &self.inner.delegate {
            libveritas::ProvableOption::Exists { value } => VeritasDelegateState::Exists {
                script_pubkey: value.script_pubkey.as_bytes().to_vec(),
                data: value.data.as_ref().map(|d| d.as_slice().to_vec()),
                offchain_data: value.offchain_data.as_ref().map(|od| VeritasOffchainData {
                    seq: od.seq,
                    data: od.data.clone(),
                }),
            },
            libveritas::ProvableOption::Empty => VeritasDelegateState::Empty,
            libveritas::ProvableOption::Unknown => VeritasDelegateState::Unknown,
        }
    }

    pub fn commitment(&self) -> VeritasCommitmentState {
        match &self.inner.commitment {
            libveritas::ProvableOption::Exists { value } => VeritasCommitmentState::Exists {
                state_root: value.onchain.state_root.to_vec(),
                prev_root: value.onchain.prev_root.map(|r| r.to_vec()),
                rolling_hash: value.onchain.rolling_hash.to_vec(),
                block_height: value.onchain.block_height,
                receipt_hash: value.receipt_hash.as_ref().map(|h| h.to_vec()),
            },
            libveritas::ProvableOption::Empty => VeritasCommitmentState::Empty,
            libveritas::ProvableOption::Unknown => VeritasCommitmentState::Unknown,
        }
    }

    pub fn is_better_than(&self, other: &VeritasZone) -> Result<bool, VeritasError> {
        self.inner
            .is_better_than(&other.inner)
            .map_err(|e| VeritasError::InvalidInput {
                message: e.to_string(),
            })
    }


    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    pub fn to_json(&self) -> Result<String, VeritasError> {
        serde_json::to_string(&self.inner).map_err(|e| VeritasError::InvalidInput {
            message: e.to_string(),
        })
    }
}

#[derive(uniffi::Object)]
pub struct VeritasQueryContext {
    inner: RwLock<QueryContext>,
}

#[uniffi::export]
impl VeritasQueryContext {
    #[uniffi::constructor]
    pub fn new() -> Self {
        VeritasQueryContext {
            inner: RwLock::new(QueryContext::new()),
        }
    }

    /// Add a handle to verify (e.g. "alice@bitcoin").
    /// If no requests are added, all handles in the message are verified.
    pub fn add_request(&self, handle: String) -> Result<(), VeritasError> {
        let sname = SName::from_str(&handle)
            .map_err(|e| VeritasError::InvalidInput {
                message: format!("invalid handle: {e}"),
            })?;
        self.inner.write().unwrap().add_request(sname);
        Ok(())
    }

    /// Add a known zone from stored bytes (from a previous verification).
    pub fn add_zone(&self, zone_bytes: Vec<u8>) -> Result<(), VeritasError> {
        let zone: Zone = borsh::from_slice(&zone_bytes).map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid zone: {e}"),
        })?;
        self.inner.write().unwrap().add_zone(zone);
        Ok(())
    }
}

#[derive(uniffi::Object)]
pub struct VeritasAnchors {
    inner: Vec<RootAnchor>,
}

#[uniffi::export]
impl VeritasAnchors {
    #[uniffi::constructor]
    pub fn from_json(json: String) -> Result<Self, VeritasError> {
        let inner: Vec<RootAnchor> = serde_json::from_str(&json)
            .map_err(|e| VeritasError::InvalidInput {
                message: format!("invalid anchors: {e}"),
            })?;
        Ok(VeritasAnchors { inner })
    }
}

#[derive(uniffi::Object)]
pub struct Veritas {
    inner: libveritas::Veritas,
}

#[uniffi::export]
impl Veritas {
    #[uniffi::constructor]
    pub fn new(anchors: &VeritasAnchors, dev_mode: bool) -> Result<Self, VeritasError> {
        let mut inner = libveritas::Veritas::from_anchors(anchors.inner.clone())
            .map_err(|e| VeritasError::InvalidInput {
                message: e.to_string(),
            })?;
        inner.set_dev_mode(dev_mode);
        Ok(Veritas { inner })
    }

    pub fn oldest_anchor(&self) -> u32 {
        self.inner.oldest_anchor()
    }

    pub fn newest_anchor(&self) -> u32 {
        self.inner.newest_anchor()
    }

    pub fn is_finalized(&self, commitment_height: u32) -> bool {
        self.inner.is_finalized(commitment_height)
    }

    pub fn sovereignty_for(&self, commitment_height: u32) -> String {
        self.inner.sovereignty_for(commitment_height).to_string()
    }

    /// Verify an encoded message against a query context.
    pub fn verify_message(
        &self,
        ctx: &VeritasQueryContext,
        msg: Vec<u8>,
    ) -> Result<Arc<VerifiedMessage>, VeritasError> {
        let ctx_guard = ctx.inner.read().unwrap();
        let msg: Message = borsh::from_slice(&msg).map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid message: {e}"),
        })?;

        let inner = self
            .inner
            .verify_message(&ctx_guard, msg)
            .map_err(|e| VeritasError::VerificationFailed {
                message: e.to_string(),
            })?;

        Ok(Arc::new(VerifiedMessage { inner }))
    }
}

#[derive(uniffi::Object)]
pub struct VerifiedMessage {
    inner: libveritas::VerifiedMessage,
}

#[uniffi::export]
impl VerifiedMessage {
    pub fn zones(&self) -> Vec<Arc<VeritasZone>> {
        self.inner
            .zones
            .iter()
            .map(|z| Arc::new(VeritasZone { inner: z.clone() }))
            .collect()
    }

    pub fn certificate(
        &self,
        handle: String,
    ) -> Result<Option<VeritasCertificate>, VeritasError> {
        let sname = SName::from_str(&handle).map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid handle: {e}"),
        })?;
        Ok(self.inner.certificate(&sname).map(|c| cert_to_record(&c)))
    }

    pub fn certificates(&self) -> Vec<VeritasCertificate> {
        self.inner
            .certificates()
            .map(|c| cert_to_record(&c))
            .collect()
    }
}

// -- Free functions --

/// Hash a message with the Spaces signed-message prefix (SHA256).
/// Returns the 32-byte digest suitable for Schnorr signing/verification.
#[uniffi::export]
pub fn hash_signable_message(msg: Vec<u8>) -> Vec<u8> {
    let secp_msg = libveritas::hash_signable_message(&msg);
    secp_msg.as_ref().to_vec()
}

/// Verify a Schnorr signature over a message using the Spaces signed-message prefix.
///
/// - `msg`: raw message bytes (prefixed and hashed internally)
/// - `signature`: 64-byte Schnorr signature
/// - `pubkey`: 32-byte x-only public key
#[uniffi::export]
pub fn verify_spaces_message(msg: Vec<u8>, signature: Vec<u8>, pubkey: Vec<u8>) -> Result<(), VeritasError> {
    let sig: [u8; 64] = signature.try_into().map_err(|_| VeritasError::InvalidInput {
        message: "signature must be 64 bytes".to_string(),
    })?;
    let pk: [u8; 32] = pubkey.try_into().map_err(|_| VeritasError::InvalidInput {
        message: "pubkey must be 32 bytes".to_string(),
    })?;
    libveritas::verify_spaces_message(&msg, &sig, &pk).map_err(|e| VeritasError::VerificationFailed {
        message: e.to_string(),
    })
}

/// Verify a raw Schnorr signature (no prefix, caller provides the 32-byte message hash).
///
/// - `msg_hash`: 32-byte SHA256 hash
/// - `signature`: 64-byte Schnorr signature
/// - `pubkey`: 32-byte x-only public key
#[uniffi::export]
pub fn verify_schnorr(msg_hash: Vec<u8>, signature: Vec<u8>, pubkey: Vec<u8>) -> Result<(), VeritasError> {
    let hash: [u8; 32] = msg_hash.try_into().map_err(|_| VeritasError::InvalidInput {
        message: "msg_hash must be 32 bytes".to_string(),
    })?;
    let sig: [u8; 64] = signature.try_into().map_err(|_| VeritasError::InvalidInput {
        message: "signature must be 64 bytes".to_string(),
    })?;
    let pk: [u8; 32] = pubkey.try_into().map_err(|_| VeritasError::InvalidInput {
        message: "pubkey must be 32 bytes".to_string(),
    })?;
    libveritas::verify_schnorr(&hash, &sig, &pk).map_err(|e| VeritasError::VerificationFailed {
        message: e.to_string(),
    })
}

/// Decode stored zone bytes to JSON.
#[uniffi::export]
pub fn decode_zone(bytes: Vec<u8>) -> Result<String, VeritasError> {
    let zone: Zone =
        borsh::from_slice(&bytes).map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid zone: {e}"),
        })?;
    serde_json::to_string(&zone).map_err(|e| VeritasError::InvalidInput {
        message: e.to_string(),
    })
}

/// Decode stored certificate bytes to JSON.
#[uniffi::export]
pub fn decode_certificate(bytes: Vec<u8>) -> Result<String, VeritasError> {
    let cert: libveritas::cert::Certificate =
        borsh::from_slice(&bytes).map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid certificate: {e}"),
        })?;
    serde_json::to_string(&cert).map_err(|e| VeritasError::InvalidInput {
        message: e.to_string(),
    })
}
