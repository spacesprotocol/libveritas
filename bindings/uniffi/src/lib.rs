use std::sync::{Arc, RwLock};

use libveritas::builder;
use libveritas::msg;
use libveritas::sname::SName;
use spaces_nums::RootAnchor;
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
pub enum DelegateState {
    Exists { script_pubkey: Vec<u8>, fallback_records: Option<Vec<u8>>, records: Option<Vec<u8>> },
    Empty,
    Unknown,
}

#[derive(uniffi::Enum)]
pub enum CommitmentState {
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
pub struct Certificate {
    pub subject: String,
    pub cert_type: String,
    pub bytes: Vec<u8>,
}

/// Data update entry for Message.update() — no cert field.
#[derive(uniffi::Record)]
pub struct DataUpdateEntry {
    pub name: String,
    pub records: Option<Vec<u8>>,
    pub delegate_records: Option<Vec<u8>>,
}

/// Update entry for MessageBuilder — includes optional cert.
#[derive(uniffi::Record)]
pub struct UpdateEntry {
    pub name: String,
    pub records: Option<Vec<u8>>,
    pub delegate_records: Option<Vec<u8>>,
    pub cert: Option<Vec<u8>>,
}

// -- Conversions --

fn cert_to_record(c: &libveritas::cert::Certificate) -> Certificate {
    let cert_type = if c.is_temporary() {
        "temporary"
    } else if c.is_leaf() {
        "final"
    } else {
        "root"
    };
    Certificate {
        subject: c.subject.to_string(),
        cert_type: cert_type.to_string(),
        bytes: c.to_bytes(),
    }
}

fn parse_data_update(entry: &DataUpdateEntry) -> Result<builder::DataUpdateRequest, VeritasError> {
    let handle = SName::from_str(&entry.name)
        .map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid name '{}': {}", entry.name, e),
        })?;

    let records = entry.records.as_ref()
        .map(|b| msg::OffchainRecords::from_slice(b))
        .transpose()
        .map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid records: {e}"),
        })?;

    let delegate_records = entry.delegate_records.as_ref()
        .map(|b| msg::OffchainRecords::from_slice(b))
        .transpose()
        .map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid delegate_records: {e}"),
        })?;

    Ok(builder::DataUpdateRequest {
        handle,
        records,
        delegate_records,
    })
}

fn parse_data_updates(entries: &[DataUpdateEntry]) -> Result<Vec<builder::DataUpdateRequest>, VeritasError> {
    entries.iter().map(parse_data_update).collect()
}

fn parse_update_entry(entry: &UpdateEntry) -> Result<builder::UpdateRequest, VeritasError> {
    let data = parse_data_update(&DataUpdateEntry {
        name: entry.name.clone(),
        records: entry.records.clone(),
        delegate_records: entry.delegate_records.clone(),
    })?;

    let cert = entry.cert.as_ref()
        .map(|b| libveritas::cert::Certificate::from_slice(b))
        .transpose()
        .map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid cert: {e}"),
        })?;

    Ok(builder::UpdateRequest { data, cert })
}

fn parse_update_entries(entries: &[UpdateEntry]) -> Result<Vec<builder::UpdateRequest>, VeritasError> {
    entries.iter().map(parse_update_entry).collect()
}

// -- Objects --

#[derive(uniffi::Object)]
pub struct Zone {
    inner: libveritas::Zone,
}

#[uniffi::export]
impl Zone {
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

    pub fn fallback_records(&self) -> Option<Vec<u8>> {
        self.inner.fallback_records.as_ref().map(|d| d.as_slice().to_vec())
    }

    pub fn records(&self) -> Option<Vec<u8>> {
        self.inner.records.as_ref().map(|d| d.as_slice().to_vec())
    }

    pub fn delegate(&self) -> DelegateState {
        match &self.inner.delegate {
            libveritas::ProvableOption::Exists { value } => DelegateState::Exists {
                script_pubkey: value.script_pubkey.as_bytes().to_vec(),
                fallback_records: value.fallback_records.as_ref().map(|d| d.as_slice().to_vec()),
                records: value.records.as_ref().map(|d| d.as_slice().to_vec()),
            },
            libveritas::ProvableOption::Empty => DelegateState::Empty,
            libveritas::ProvableOption::Unknown => DelegateState::Unknown,
        }
    }

    pub fn commitment(&self) -> CommitmentState {
        match &self.inner.commitment {
            libveritas::ProvableOption::Exists { value } => CommitmentState::Exists {
                state_root: value.onchain.state_root.to_vec(),
                prev_root: value.onchain.prev_root.map(|r| r.to_vec()),
                rolling_hash: value.onchain.rolling_hash.to_vec(),
                block_height: value.onchain.block_height,
                receipt_hash: value.receipt_hash.as_ref().map(|h| h.to_vec()),
            },
            libveritas::ProvableOption::Empty => CommitmentState::Empty,
            libveritas::ProvableOption::Unknown => CommitmentState::Unknown,
        }
    }

    pub fn is_better_than(&self, other: &Zone) -> Result<bool, VeritasError> {
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
pub struct QueryContext {
    inner: RwLock<msg::QueryContext>,
}

#[uniffi::export]
impl QueryContext {
    #[uniffi::constructor]
    pub fn new() -> Self {
        QueryContext {
            inner: RwLock::new(msg::QueryContext::new()),
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
        let zone = libveritas::Zone::from_slice(&zone_bytes).map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid zone: {e}"),
        })?;
        self.inner.write().unwrap().add_zone(zone);
        Ok(())
    }
}

#[derive(uniffi::Object)]
pub struct Message {
    inner: RwLock<msg::Message>,
}

#[uniffi::export]
impl Message {
    /// Decode a message from borsh bytes.
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Result<Self, VeritasError> {
        let inner = msg::Message::from_slice(&bytes)
            .map_err(|e| VeritasError::InvalidInput {
                message: format!("invalid message: {e}"),
            })?;
        Ok(Message { inner: RwLock::new(inner) })
    }

    /// Serialize the message to borsh bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.read().unwrap().to_bytes()
    }

    /// Update records on this message.
    ///
    /// - `name`: handle string (e.g. "alice@bitcoin", "@bitcoin", "#12-12-0")
    /// - `records`: borsh-encoded OffchainRecords (optional)
    /// - `delegate_records`: borsh-encoded OffchainRecords (optional)
    pub fn update(&self, updates: Vec<DataUpdateEntry>) -> Result<(), VeritasError> {
        let reqs = parse_data_updates(&updates)?;
        self.inner.write().unwrap().update(reqs);
        Ok(())
    }
}

/// Builder for constructing messages from update requests and chain proofs.
#[derive(uniffi::Object)]
pub struct MessageBuilder {
    inner: RwLock<Option<builder::MessageBuilder>>,
}

#[uniffi::export]
impl MessageBuilder {
    /// Create a builder from a list of update entries.
    #[uniffi::constructor]
    pub fn new(requests: Vec<UpdateEntry>) -> Result<Self, VeritasError> {
        let reqs = parse_update_entries(&requests)?;
        Ok(MessageBuilder {
            inner: RwLock::new(Some(builder::MessageBuilder::new(reqs))),
        })
    }

    /// Returns the chain proof request as JSON.
    ///
    /// Send this to the provider/fabric to get the chain proofs needed for `build()`.
    pub fn chain_proof_request(&self) -> Result<String, VeritasError> {
        let guard = self.inner.read().unwrap();
        let builder = guard
            .as_ref()
            .ok_or_else(|| VeritasError::InvalidInput {
                message: "builder already consumed by build()".to_string(),
            })?;
        serde_json::to_string(&builder.chain_proof_request())
            .map_err(|e| VeritasError::InvalidInput {
                message: e.to_string(),
            })
    }

    /// Build the message from a borsh-encoded ChainProof.
    ///
    /// Consumes the builder — cannot be called twice.
    pub fn build(&self, chain_proof: Vec<u8>) -> Result<Arc<Message>, VeritasError> {
        let builder = self
            .inner
            .write()
            .unwrap()
            .take()
            .ok_or_else(|| VeritasError::InvalidInput {
                message: "builder already consumed by build()".to_string(),
            })?;
        let chain = msg::ChainProof::from_slice(&chain_proof)
            .map_err(|e| VeritasError::InvalidInput {
                message: format!("invalid chain proof: {e}"),
            })?;
        let msg = builder
            .build(chain)
            .map_err(|e| VeritasError::InvalidInput {
                message: e.to_string(),
            })?;
        Ok(Arc::new(Message { inner: RwLock::new(msg) }))
    }
}

#[derive(uniffi::Object)]
pub struct Anchors {
    inner: Vec<RootAnchor>,
}

#[uniffi::export]
impl Anchors {
    #[uniffi::constructor]
    pub fn from_json(json: String) -> Result<Self, VeritasError> {
        let inner: Vec<RootAnchor> = serde_json::from_str(&json)
            .map_err(|e| VeritasError::InvalidInput {
                message: format!("invalid anchors: {e}"),
            })?;
        Ok(Anchors { inner })
    }
}

// ── Record / RecordSet ────────────────────────────────────────────

/// A single SIP-7 record.
#[derive(uniffi::Enum)]
pub enum Record {
    Seq { version: u64 },
    Txt { key: String, value: String },
    Blob { key: String, value: Vec<u8> },
    Unknown { rtype: u8, rdata: Vec<u8> },
}

impl From<sip7::Record> for Record {
    fn from(r: sip7::Record) -> Self {
        match r {
            sip7::Record::Seq(version) => Record::Seq { version },
            sip7::Record::Txt { key, value } => Record::Txt { key, value },
            sip7::Record::Blob { key, value } => Record::Blob { key, value },
            sip7::Record::Unknown { rtype, rdata } => Record::Unknown { rtype, rdata },
        }
    }
}

impl From<Record> for sip7::Record {
    fn from(r: Record) -> Self {
        match r {
            Record::Seq { version } => sip7::Record::seq(version),
            Record::Txt { key, value } => sip7::Record::txt(&key, &value),
            Record::Blob { key, value } => sip7::Record::blob(&key, value),
            Record::Unknown { rtype, rdata } => sip7::Record::unknown(rtype, rdata),
        }
    }
}

/// SIP-7 record set — wire-format encoded records.
#[derive(uniffi::Object)]
pub struct RecordSet {
    inner: sip7::RecordSet,
}

#[uniffi::export]
impl RecordSet {
    /// Wrap raw wire bytes (lazy — no parsing until unpack).
    #[uniffi::constructor]
    pub fn new(data: Vec<u8>) -> Self {
        RecordSet { inner: sip7::RecordSet::new(data) }
    }

    /// Pack records into wire format.
    #[uniffi::constructor(name = "pack")]
    pub fn pack(records: Vec<Record>) -> Result<Self, VeritasError> {
        let sip_records: Vec<sip7::Record> = records.into_iter().map(Into::into).collect();
        let inner = sip7::RecordSet::pack(sip_records)
            .map_err(|e| VeritasError::InvalidInput { message: e.to_string() })?;
        Ok(RecordSet { inner })
    }

    /// Raw wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_slice().to_vec()
    }

    /// Parse all records.
    pub fn unpack(&self) -> Result<Vec<Record>, VeritasError> {
        self.inner.unpack()
            .map(|records| records.into_iter().map(Into::into).collect())
            .map_err(|e| VeritasError::InvalidInput { message: e.to_string() })
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The 32-byte signing hash (Spaces signed-message prefix + SHA256).
    pub fn signing_id(&self) -> Vec<u8> {
        let msg = libveritas::hash_signable_message(self.inner.as_slice());
        msg.as_ref().to_vec()
    }
}

// ── OffchainRecords helpers ──────────────────────────────────────

/// Create borsh-encoded OffchainRecords from a RecordSet and 64-byte Schnorr signature.
#[uniffi::export]
pub fn create_offchain_records(record_set: &RecordSet, signature: Vec<u8>) -> Result<Vec<u8>, VeritasError> {
    let sig: [u8; 64] = signature.try_into().map_err(|_| VeritasError::InvalidInput {
        message: "signature must be 64 bytes".to_string(),
    })?;
    let offchain = msg::OffchainRecords::new(
        record_set.inner.clone(),
        libveritas::cert::Signature(sig),
    );
    Ok(offchain.to_bytes())
}

#[derive(uniffi::Object)]
pub struct Veritas {
    inner: libveritas::Veritas,
}

#[uniffi::export]
impl Veritas {
    #[uniffi::constructor]
    pub fn new(anchors: &Anchors) -> Result<Self, VeritasError> {
        let inner = libveritas::Veritas::new()
            .with_anchors(anchors.inner.clone())
            .map_err(|e| VeritasError::InvalidInput {
                message: e.to_string(),
            })?;
        Ok(Veritas { inner })
    }

    #[uniffi::constructor(name = "with_dev_mode")]
    pub fn with_dev_mode(anchors: &Anchors) -> Result<Self, VeritasError> {
        let inner = libveritas::Veritas::new()
            .with_anchors(anchors.inner.clone())
            .map_err(|e| VeritasError::InvalidInput {
                message: e.to_string(),
            })?
            .with_dev_mode(true);
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

    /// Verify a message against a query context.
    pub fn verify_message(
        &self,
        ctx: &QueryContext,
        msg: &Message,
    ) -> Result<Arc<VerifiedMessage>, VeritasError> {
        let ctx_guard = ctx.inner.read().unwrap();
        let msg_inner = msg.inner.read().unwrap();

        let inner = self
            .inner
            .verify_message(&ctx_guard, msg_inner.clone())
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
    pub fn zones(&self) -> Vec<Arc<Zone>> {
        self.inner
            .zones
            .iter()
            .map(|z| Arc::new(Zone { inner: z.clone() }))
            .collect()
    }

    pub fn certificate(
        &self,
        handle: String,
    ) -> Result<Option<Certificate>, VeritasError> {
        let sname = SName::from_str(&handle).map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid handle: {e}"),
        })?;
        Ok(self.inner.certificate(&sname).map(|c| cert_to_record(&c)))
    }

    pub fn certificates(&self) -> Vec<Certificate> {
        self.inner
            .certificates()
            .map(|c| cert_to_record(&c))
            .collect()
    }

    /// Get the verified message for rebroadcasting or updating.
    pub fn message(&self) -> Arc<Message> {
        Arc::new(Message {
            inner: RwLock::new(self.inner.message.clone()),
        })
    }

    /// Get the verified message as borsh bytes.
    pub fn message_bytes(&self) -> Vec<u8> {
        self.inner.message.to_bytes()
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
    let zone = libveritas::Zone::from_slice(&bytes)
        .map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid zone: {e}"),
        })?;
    serde_json::to_string(&zone).map_err(|e| VeritasError::InvalidInput {
        message: e.to_string(),
    })
}

/// Decode stored certificate bytes to JSON.
#[uniffi::export]
pub fn decode_certificate(bytes: Vec<u8>) -> Result<String, VeritasError> {
    let cert = libveritas::cert::Certificate::from_slice(&bytes)
        .map_err(|e| VeritasError::InvalidInput {
            message: format!("invalid certificate: {e}"),
        })?;
    serde_json::to_string(&cert).map_err(|e| VeritasError::InvalidInput {
        message: e.to_string(),
    })
}
