use std::sync::{Arc, RwLock};

use libveritas::builder;
use libveritas::msg;
use spaces_nums::RootAnchor;
use spaces_nums::num_id::NumId;
use spaces_protocol::bitcoin::ScriptBuf;
use spaces_protocol::slabel::SLabel;
use spaces_protocol::sname::SName;
use std::str::FromStr;

uniffi::setup_scaffolding!();

// -- Errors --

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VeritasError {
    #[error("{msg}")]
    InvalidInput { msg: String },
    #[error("{msg}")]
    VerificationFailed { msg: String },
}

// -- Enums --

#[derive(uniffi::Enum)]
pub enum DelegateState {
    Exists {
        script_pubkey: Vec<u8>,
        fallback_records: Vec<u8>,
        records: Vec<u8>,
    },
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
pub struct TrustSet {
    pub id: Vec<u8>,
    pub roots: Vec<Vec<u8>>,
}

/// Data update entry for Message.update() — no cert field.
#[derive(uniffi::Record)]
pub struct DataUpdateEntry {
    pub name: String,
    pub records: Option<Vec<u8>>,
    pub delegate_records: Option<Vec<u8>>,
}

// -- Conversions --

fn trust_set_from_inner(ts: &libveritas::TrustSet) -> TrustSet {
    TrustSet {
        id: ts.id.to_vec(),
        roots: ts.roots.iter().map(|r| r.to_vec()).collect(),
    }
}

fn parse_data_update(entry: &DataUpdateEntry) -> Result<builder::DataUpdateRequest, VeritasError> {
    let handle = SName::from_str(&entry.name).map_err(|e| VeritasError::InvalidInput {
        msg: format!("invalid name '{}': {}", entry.name, e),
    })?;

    let records = entry
        .records
        .as_ref()
        .map(|b| sip7::RecordSet::new(b.clone()));

    let delegate_records = entry
        .delegate_records
        .as_ref()
        .map(|b| sip7::RecordSet::new(b.clone()));

    Ok(builder::DataUpdateRequest {
        handle,
        records,
        delegate_records,
    })
}

fn parse_data_updates(
    entries: &[DataUpdateEntry],
) -> Result<Vec<builder::DataUpdateRequest>, VeritasError> {
    entries.iter().map(parse_data_update).collect()
}

// -- Objects --

#[derive(uniffi::Record)]
pub struct Zone {
    pub anchor: u32,
    pub sovereignty: String,
    pub handle: String,
    pub canonical: String,
    pub alias: Option<String>,
    pub script_pubkey: Vec<u8>,
    pub num_id: Option<String>,
    pub records: Vec<u8>,
    pub fallback_records: Vec<u8>,
    pub delegate: DelegateState,
    pub commitment: CommitmentState,
}

fn zone_from_inner(z: &libveritas::Zone) -> Zone {
    Zone {
        anchor: z.anchor,
        sovereignty: z.sovereignty.to_string(),
        handle: z.handle.to_string(),
        canonical: z.canonical.to_string(),
        alias: z.alias.as_ref().map(|a| a.to_string()),
        script_pubkey: z.script_pubkey.as_bytes().to_vec(),
        num_id: z.num_id.map(|n| n.to_string()),
        records: z.records.as_slice().to_vec(),
        fallback_records: z.fallback_records.as_slice().to_vec(),
        delegate: match &z.delegate {
            libveritas::ProvableOption::Exists { value } => DelegateState::Exists {
                script_pubkey: value.script_pubkey.as_bytes().to_vec(),
                fallback_records: value.fallback_records.as_slice().to_vec(),
                records: value.records.as_slice().to_vec(),
            },
            libveritas::ProvableOption::Empty => DelegateState::Empty,
            libveritas::ProvableOption::Unknown => DelegateState::Unknown,
        },
        commitment: match &z.commitment {
            libveritas::ProvableOption::Exists { value } => CommitmentState::Exists {
                state_root: value.onchain.state_root.to_vec(),
                prev_root: value.onchain.prev_root.map(|r| r.to_vec()),
                rolling_hash: value.onchain.rolling_hash.to_vec(),
                block_height: value.onchain.block_height,
                receipt_hash: value.receipt_hash.as_ref().map(|h| h.to_vec()),
            },
            libveritas::ProvableOption::Empty => CommitmentState::Empty,
            libveritas::ProvableOption::Unknown => CommitmentState::Unknown,
        },
    }
}

fn zone_to_inner(z: &Zone) -> Result<libveritas::Zone, VeritasError> {
    let handle = SName::from_str(&z.handle).map_err(|e| VeritasError::InvalidInput {
        msg: format!("invalid handle: {e}"),
    })?;
    let canonical = SName::from_str(&z.canonical).map_err(|e| VeritasError::InvalidInput {
        msg: format!("invalid canonical: {e}"),
    })?;
    let alias = z
        .alias
        .as_ref()
        .map(|a| SLabel::from_str_unprefixed(a))
        .transpose()
        .map_err(|e| VeritasError::InvalidInput {
            msg: format!("invalid alias: {e}"),
        })?;
    let num_id = z
        .num_id
        .as_ref()
        .map(|n| NumId::from_str(n))
        .transpose()
        .map_err(|e| VeritasError::InvalidInput {
            msg: format!("invalid num_id: {e}"),
        })?;
    let delegate = match &z.delegate {
        DelegateState::Exists {
            script_pubkey,
            fallback_records,
            records,
        } => libveritas::ProvableOption::Exists {
            value: libveritas::Delegate {
                script_pubkey: ScriptBuf::from_bytes(script_pubkey.clone()),
                fallback_records: sip7::RecordSet::new(fallback_records.clone()),
                records: sip7::RecordSet::new(records.clone()),
            },
        },
        DelegateState::Empty => libveritas::ProvableOption::Empty,
        DelegateState::Unknown => libveritas::ProvableOption::Unknown,
    };
    let commitment = match &z.commitment {
        CommitmentState::Exists {
            state_root,
            prev_root,
            rolling_hash,
            block_height,
            receipt_hash,
        } => {
            let mut sr = [0u8; 32];
            sr.copy_from_slice(state_root);
            let mut rh = [0u8; 32];
            rh.copy_from_slice(rolling_hash);
            let pr = prev_root.as_ref().map(|p| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(p);
                arr
            });
            let rh2 = receipt_hash.as_ref().map(|h| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(h);
                arr
            });
            libveritas::ProvableOption::Exists {
                value: libveritas::CommitmentInfo {
                    onchain: spaces_nums::Commitment {
                        state_root: sr,
                        prev_root: pr,
                        rolling_hash: rh,
                        block_height: *block_height,
                    },
                    receipt_hash: rh2,
                },
            }
        }
        CommitmentState::Empty => libveritas::ProvableOption::Empty,
        CommitmentState::Unknown => libveritas::ProvableOption::Unknown,
    };

    Ok(libveritas::Zone {
        anchor: z.anchor,
        sovereignty: match z.sovereignty.as_str() {
            "sovereign" => libveritas::SovereigntyState::Sovereign,
            "pending" => libveritas::SovereigntyState::Pending,
            _ => libveritas::SovereigntyState::Dependent,
        },
        handle,
        canonical,
        alias,
        script_pubkey: ScriptBuf::from_bytes(z.script_pubkey.clone()),
        records: sip7::RecordSet::new(z.records.clone()),
        fallback_records: sip7::RecordSet::new(z.fallback_records.clone()),
        delegate,
        commitment,
        num_id,
    })
}

#[derive(uniffi::Object)]
pub struct QueryContext {
    inner: RwLock<msg::QueryContext>,
}

impl Default for QueryContext {
    fn default() -> Self {
        Self::new()
    }
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
        let sname = SName::from_str(&handle).map_err(|e| VeritasError::InvalidInput {
            msg: format!("invalid handle: {e}"),
        })?;
        self.inner.write().unwrap().add_request(sname);
        Ok(())
    }

    /// Add a known zone from stored bytes (from a previous verification).
    pub fn add_zone(&self, zone_bytes: Vec<u8>) -> Result<(), VeritasError> {
        let zone =
            libveritas::Zone::from_slice(&zone_bytes).map_err(|e| VeritasError::InvalidInput {
                msg: format!("invalid zone: {e}"),
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
    /// Decode a message from bytes.
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Result<Self, VeritasError> {
        let inner = msg::Message::from_slice(&bytes).map_err(|e| VeritasError::InvalidInput {
            msg: format!("invalid message: {e}"),
        })?;
        Ok(Message {
            inner: RwLock::new(inner),
        })
    }

    /// Serialize the message to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.read().unwrap().to_bytes()
    }

    /// Update records on this message.
    pub fn update(&self, updates: Vec<DataUpdateEntry>) -> Result<(), VeritasError> {
        let reqs = parse_data_updates(&updates)?;
        self.inner.write().unwrap().update(reqs);
        Ok(())
    }

    /// Set records on the message for a canonical name.
    pub fn set_records(
        &self,
        canonical: String,
        records_bytes: Vec<u8>,
    ) -> Result<(), VeritasError> {
        let sname = SName::from_str(&canonical).map_err(|e| VeritasError::InvalidInput {
            msg: format!("invalid canonical: {e}"),
        })?;
        self.inner
            .write()
            .unwrap()
            .set_records(&sname, sip7::RecordSet::new(records_bytes));
        Ok(())
    }

    /// Set delegate records on the message for a canonical name.
    pub fn set_delegate_records(
        &self,
        canonical: String,
        records_bytes: Vec<u8>,
    ) -> Result<(), VeritasError> {
        let sname = SName::from_str(&canonical).map_err(|e| VeritasError::InvalidInput {
            msg: format!("invalid canonical: {e}"),
        })?;
        self.inner
            .write()
            .unwrap()
            .set_delegate_records(&sname, sip7::RecordSet::new(records_bytes));
        Ok(())
    }
}

/// An unsigned record set pending signature.
#[derive(uniffi::Object)]
pub struct UnsignedRecordSet {
    inner: RwLock<msg::UnsignedRecordSet>,
}

#[uniffi::export]
impl UnsignedRecordSet {
    /// The original handle name (before flattening).
    pub fn handle(&self) -> String {
        self.inner.read().unwrap().handle.to_string()
    }

    /// The canonical/flattened name.
    pub fn canonical(&self) -> String {
        self.inner.read().unwrap().canonical.to_string()
    }

    /// Whether these are delegate records.
    pub fn is_delegate(&self) -> bool {
        self.inner.read().unwrap().delegate
    }

    /// Current sig flags.
    pub fn flags(&self) -> u8 {
        self.inner.read().unwrap().flags
    }

    /// Set sig flags (e.g. `SIG_PRIMARY_ZONE`).
    pub fn set_flags(&self, flags: u8) {
        self.inner.write().unwrap().flags = flags;
    }

    /// The raw signable bytes (before hashing). Use when the signer doesn't take a digest.
    pub fn signable_bytes(&self) -> Vec<u8> {
        self.inner.read().unwrap().signable_bytes()
    }

    /// The 32-byte signing hash (Spaces signed-message prefix + SHA256).
    pub fn signing_id(&self) -> Vec<u8> {
        self.inner.read().unwrap().signing_id().to_vec()
    }

    /// Pack the Sig record with the given signature. Returns signed RecordSet wire bytes.
    pub fn pack_sig(&self, signature: Vec<u8>) -> Vec<u8> {
        self.inner
            .read()
            .unwrap()
            .pack_sig(signature)
            .as_slice()
            .to_vec()
    }
}

/// Result of building a message.
#[derive(uniffi::Record)]
pub struct BuildResult {
    pub message: Arc<Message>,
    pub unsigned: Vec<Arc<UnsignedRecordSet>>,
}

/// Builder for constructing messages from update requests and chain proofs.
#[derive(uniffi::Object)]
pub struct MessageBuilder {
    inner: RwLock<Option<builder::MessageBuilder>>,
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl MessageBuilder {
    /// Create an empty builder.
    #[uniffi::constructor]
    pub fn new() -> Self {
        MessageBuilder {
            inner: RwLock::new(Some(builder::MessageBuilder::new())),
        }
    }

    /// Add a .spacecert chain with records (sip7 wire bytes).
    pub fn add_handle(
        &self,
        chain_bytes: Vec<u8>,
        records_bytes: Vec<u8>,
    ) -> Result<(), VeritasError> {
        let chain = libveritas::cert::CertificateChain::from_slice(&chain_bytes).map_err(|e| {
            VeritasError::InvalidInput {
                msg: format!("invalid chain: {e}"),
            }
        })?;
        let records = sip7::RecordSet::new(records_bytes);
        self.inner
            .write()
            .unwrap()
            .as_mut()
            .ok_or_else(|| VeritasError::InvalidInput {
                msg: "builder already consumed by build()".to_string(),
            })?
            .add_handle(chain, records);
        Ok(())
    }

    /// Add all certificates from a .spacecert chain.
    pub fn add_chain(&self, chain_bytes: Vec<u8>) -> Result<(), VeritasError> {
        let chain = libveritas::cert::CertificateChain::from_slice(&chain_bytes).map_err(|e| {
            VeritasError::InvalidInput {
                msg: format!("invalid chain: {e}"),
            }
        })?;
        self.inner
            .write()
            .unwrap()
            .as_mut()
            .ok_or_else(|| VeritasError::InvalidInput {
                msg: "builder already consumed by build()".to_string(),
            })?
            .add_chain(chain);
        Ok(())
    }

    /// Add a single certificate.
    pub fn add_cert(&self, cert_bytes: Vec<u8>) -> Result<(), VeritasError> {
        let cert = libveritas::cert::Certificate::from_slice(&cert_bytes).map_err(|e| {
            VeritasError::InvalidInput {
                msg: format!("invalid cert: {e}"),
            }
        })?;
        self.inner
            .write()
            .unwrap()
            .as_mut()
            .ok_or_else(|| VeritasError::InvalidInput {
                msg: "builder already consumed by build()".to_string(),
            })?
            .add_cert(cert);
        Ok(())
    }

    /// Add records for a handle (sip7 wire bytes).
    pub fn add_records(&self, handle: String, records_bytes: Vec<u8>) -> Result<(), VeritasError> {
        let sname = SName::from_str(&handle).map_err(|e| VeritasError::InvalidInput {
            msg: format!("invalid handle: {e}"),
        })?;
        let records = sip7::RecordSet::new(records_bytes);
        self.inner
            .write()
            .unwrap()
            .as_mut()
            .ok_or_else(|| VeritasError::InvalidInput {
                msg: "builder already consumed by build()".to_string(),
            })?
            .add_records(sname, records);
        Ok(())
    }

    /// Add a full data update (records + optional delegate records).
    pub fn add_update(&self, entry: DataUpdateEntry) -> Result<(), VeritasError> {
        let update = parse_data_update(&entry)?;
        self.inner
            .write()
            .unwrap()
            .as_mut()
            .ok_or_else(|| VeritasError::InvalidInput {
                msg: "builder already consumed by build()".to_string(),
            })?
            .add_update(update);
        Ok(())
    }

    /// Returns the chain proof request as JSON.
    ///
    /// Send this to the provider/fabric to get the chain proofs needed for `build()`.
    pub fn chain_proof_request(&self) -> Result<String, VeritasError> {
        let guard = self.inner.read().unwrap();
        let builder = guard.as_ref().ok_or_else(|| VeritasError::InvalidInput {
            msg: "builder already consumed by build()".to_string(),
        })?;
        serde_json::to_string(&builder.chain_proof_request())
            .map_err(|e| VeritasError::InvalidInput { msg: e.to_string() })
    }

    /// Build the message from a ChainProof.
    ///
    /// Consumes the builder — cannot be called twice.
    /// Returns the message and unsigned record sets that need signing.
    pub fn build(&self, chain_proof: Vec<u8>) -> Result<BuildResult, VeritasError> {
        let builder =
            self.inner
                .write()
                .unwrap()
                .take()
                .ok_or_else(|| VeritasError::InvalidInput {
                    msg: "builder already consumed by build()".to_string(),
                })?;
        let chain =
            msg::ChainProof::from_slice(&chain_proof).map_err(|e| VeritasError::InvalidInput {
                msg: format!("invalid chain proof: {e}"),
            })?;
        let (inner_msg, unsigned) = builder
            .build(chain)
            .map_err(|e| VeritasError::InvalidInput { msg: e.to_string() })?;
        Ok(BuildResult {
            message: Arc::new(Message {
                inner: RwLock::new(inner_msg),
            }),
            unsigned: unsigned
                .into_iter()
                .map(|u| {
                    Arc::new(UnsignedRecordSet {
                        inner: RwLock::new(u),
                    })
                })
                .collect(),
        })
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
        let inner: Vec<RootAnchor> =
            serde_json::from_str(&json).map_err(|e| VeritasError::InvalidInput {
                msg: format!("invalid anchors: {e}"),
            })?;
        Ok(Anchors { inner })
    }

    pub fn compute_trust_set(&self) -> TrustSet {
        trust_set_from_inner(&libveritas::compute_trust_set(&self.inner))
    }
}

// ── Record / RecordSet ────────────────────────────────────────────

/// A single SIP-7 record (for constructing/packing).
#[derive(uniffi::Enum)]
pub enum Record {
    Seq {
        version: u64,
    },
    Txt {
        key: String,
        value: Vec<String>,
    },
    Addr {
        key: String,
        value: Vec<String>,
    },
    Blob {
        key: String,
        value: Vec<u8>,
    },
    Sig {
        flags: u8,
        canonical: String,
        handle: String,
        sig: Vec<u8>,
    },
    Unknown {
        rtype: u8,
        rdata: Vec<u8>,
    },
}

/// A parsed SIP-7 record (from unpacking). Includes `Malformed` for invalid rdata.
#[derive(uniffi::Enum)]
pub enum ParsedRecord {
    Seq {
        version: u64,
    },
    Txt {
        key: String,
        value: Vec<String>,
    },
    Addr {
        key: String,
        value: Vec<String>,
    },
    Blob {
        key: String,
        value: Vec<u8>,
    },
    Sig {
        flags: u8,
        canonical: String,
        handle: String,
        sig: Vec<u8>,
    },
    Malformed {
        rtype: u8,
        rdata: Vec<u8>,
    },
    Unknown {
        rtype: u8,
        rdata: Vec<u8>,
    },
}

impl<'a> From<sip7::ParsedRecord<'a>> for ParsedRecord {
    fn from(p: sip7::ParsedRecord<'a>) -> Self {
        match p {
            sip7::ParsedRecord::Seq(version) => ParsedRecord::Seq { version },
            sip7::ParsedRecord::Txt { key, value } => ParsedRecord::Txt {
                key: String::from(key),
                value: value.to_vec().into_iter().map(String::from).collect(),
            },
            sip7::ParsedRecord::Addr { key, value } => ParsedRecord::Addr {
                key: String::from(key),
                value: value.to_vec().into_iter().map(String::from).collect(),
            },
            sip7::ParsedRecord::Blob { key, value } => ParsedRecord::Blob {
                key: String::from(key),
                value: value.to_vec(),
            },
            sip7::ParsedRecord::Sig(sig) => ParsedRecord::Sig {
                flags: sig.flags,
                canonical: sig.canonical.to_owned().to_string(),
                handle: sig.handle.to_owned().to_string(),
                sig: sig.sig.to_vec(),
            },
            sip7::ParsedRecord::Malformed { rtype, rdata } => ParsedRecord::Malformed {
                rtype,
                rdata: rdata.to_vec(),
            },
            sip7::ParsedRecord::Unknown { rtype, rdata } => ParsedRecord::Unknown {
                rtype,
                rdata: rdata.to_vec(),
            },
        }
    }
}

impl From<sip7::Record> for Record {
    fn from(r: sip7::Record) -> Self {
        match r {
            sip7::Record::Seq(version) => Record::Seq { version },
            sip7::Record::Txt { key, value } => Record::Txt { key, value },
            sip7::Record::Addr { key, value } => Record::Addr { key, value },
            sip7::Record::Blob { key, value } => Record::Blob { key, value },
            sip7::Record::Sig {
                flags,
                canonical,
                handle,
                sig,
            } => Record::Sig {
                flags,
                canonical: canonical.to_string(),
                handle: handle.to_string(),
                sig,
            },
            sip7::Record::Unknown { rtype, rdata } => Record::Unknown { rtype, rdata },
        }
    }
}

impl From<Record> for sip7::Record {
    fn from(r: Record) -> Self {
        match r {
            Record::Seq { version } => sip7::Record::seq(version),
            Record::Txt { key, value } => {
                let refs: Vec<&str> = value.iter().map(|s| s.as_str()).collect();
                sip7::Record::txt(&key, &refs)
            }
            Record::Addr { key, value } => {
                let refs: Vec<&str> = value.iter().map(|s| s.as_str()).collect();
                sip7::Record::addr(&key, &refs)
            }
            Record::Blob { key, value } => sip7::Record::blob(&key, value),
            Record::Sig {
                flags,
                canonical,
                handle,
                sig,
            } => {
                let canonical = SName::from_str(&canonical).expect("valid canonical");
                let handle = if handle.is_empty() {
                    SName::empty()
                } else {
                    SName::from_str(&handle).expect("valid handle")
                };
                sip7::Record::sig(canonical, handle, sig, flags)
            }
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
        RecordSet {
            inner: sip7::RecordSet::new(data),
        }
    }

    /// Pack records into wire format.
    #[uniffi::constructor(name = "pack")]
    pub fn pack(records: Vec<Record>) -> Result<Self, VeritasError> {
        let sip_records: Vec<sip7::Record> = records.into_iter().map(Into::into).collect();
        let inner = sip7::RecordSet::pack(sip_records)
            .map_err(|e| VeritasError::InvalidInput { msg: e.to_string() })?;
        Ok(RecordSet { inner })
    }

    /// Raw wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_slice().to_vec()
    }

    /// Parse all records.
    pub fn unpack(&self) -> Result<Vec<ParsedRecord>, VeritasError> {
        self.inner
            .unpack()
            .map(|records| records.into_iter().map(Into::into).collect())
            .map_err(|e| VeritasError::InvalidInput { msg: e.to_string() })
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
            .map_err(|e| VeritasError::InvalidInput { msg: e.to_string() })?;
        Ok(Veritas { inner })
    }

    pub fn oldest_anchor(&self) -> u32 {
        self.inner.oldest_anchor()
    }

    pub fn newest_anchor(&self) -> u32 {
        self.inner.newest_anchor()
    }

    pub fn compute_trust_set(&self) -> TrustSet {
        trust_set_from_inner(&self.inner.compute_trust_set())
    }

    pub fn is_finalized(&self, commitment_height: u32) -> bool {
        self.inner.is_finalized(commitment_height)
    }

    pub fn sovereignty_for(&self, commitment_height: u32) -> String {
        self.inner.sovereignty_for(commitment_height).to_string()
    }

    /// Verify a message with default options.
    pub fn verify(
        &self,
        ctx: &QueryContext,
        msg: &Message,
    ) -> Result<Arc<VerifiedMessage>, VeritasError> {
        let ctx_guard = ctx.inner.read().unwrap();
        let msg_inner = msg.inner.read().unwrap();

        let inner = self
            .inner
            .verify(&ctx_guard, msg_inner.clone())
            .map_err(|e| VeritasError::VerificationFailed { msg: e.to_string() })?;

        Ok(Arc::new(VerifiedMessage { inner }))
    }

    /// Verify a message with option flags (combine with bitwise OR).
    pub fn verify_with_options(
        &self,
        ctx: &QueryContext,
        msg: &Message,
        options: u32,
    ) -> Result<Arc<VerifiedMessage>, VeritasError> {
        let ctx_guard = ctx.inner.read().unwrap();
        let msg_inner = msg.inner.read().unwrap();

        let inner = self
            .inner
            .verify_with_options(&ctx_guard, msg_inner.clone(), options)
            .map_err(|e| VeritasError::VerificationFailed { msg: e.to_string() })?;

        Ok(Arc::new(VerifiedMessage { inner }))
    }
}

#[derive(uniffi::Object)]
pub struct VerifiedMessage {
    inner: libveritas::VerifiedMessage,
}

#[uniffi::export]
impl VerifiedMessage {
    pub fn root_id(&self) -> Vec<u8> {
        self.inner.root_id.to_vec()
    }

    pub fn zones(&self) -> Vec<Zone> {
        self.inner.zones.iter().map(zone_from_inner).collect()
    }

    pub fn certificates(&self) -> Vec<Vec<u8>> {
        self.inner.certificates().map(|c| c.to_bytes()).collect()
    }

    /// Get the verified message for rebroadcasting or updating.
    pub fn message(&self) -> Arc<Message> {
        Arc::new(Message {
            inner: RwLock::new(self.inner.message.clone()),
        })
    }

    /// Get the verified message as bytes.
    pub fn message_bytes(&self) -> Vec<u8> {
        self.inner.message.to_bytes()
    }
}

/// Batched iterative resolver for nested handle names.
#[derive(uniffi::Object)]
pub struct Lookup {
    inner: libveritas::names::Lookup,
}

#[uniffi::export]
impl Lookup {
    /// Create a lookup from a list of handle name strings.
    #[uniffi::constructor]
    pub fn new(names: Vec<String>) -> Result<Self, VeritasError> {
        let snames: Vec<SName> = names
            .iter()
            .map(|n| {
                SName::from_str(n).map_err(|e| VeritasError::InvalidInput {
                    msg: format!("invalid name '{}': {}", n, e),
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Lookup {
            inner: libveritas::names::Lookup::new(snames),
        })
    }

    /// Returns the first batch of handles to look up.
    pub fn start(&self) -> Vec<String> {
        self.inner.start().iter().map(|s| s.to_string()).collect()
    }

    /// Feed zones from a resolveAll response.
    /// Returns the next batch of handles to look up (empty = done).
    pub fn advance(&self, zones: Vec<Zone>) -> Result<Vec<String>, VeritasError> {
        let inner_zones: Vec<libveritas::Zone> =
            zones.iter().map(zone_to_inner).collect::<Result<_, _>>()?;
        Ok(self
            .inner
            .advance(&inner_zones)
            .iter()
            .map(|s| s.to_string())
            .collect())
    }

    /// Expand zone handles using the alias map accumulated during resolution.
    pub fn expand_zones(&self, zones: Vec<Zone>) -> Result<Vec<Zone>, VeritasError> {
        let mut inner_zones: Vec<libveritas::Zone> =
            zones.iter().map(zone_to_inner).collect::<Result<_, _>>()?;
        self.inner.expand_zones(&mut inner_zones);
        Ok(inner_zones.iter().map(zone_from_inner).collect())
    }
}

// -- Free functions --

/// Create a .spacecert file from a subject name and certificate bytes.
#[uniffi::export]
pub fn create_certificate_chain(
    subject: String,
    cert_bytes_list: Vec<Vec<u8>>,
) -> Result<Vec<u8>, VeritasError> {
    let sname = SName::from_str(&subject).map_err(|e| VeritasError::InvalidInput {
        msg: format!("invalid subject: {e}"),
    })?;
    let certs: Vec<libveritas::cert::Certificate> = cert_bytes_list
        .iter()
        .map(|b| {
            libveritas::cert::Certificate::from_slice(b).map_err(|e| VeritasError::InvalidInput {
                msg: format!("invalid cert: {e}"),
            })
        })
        .collect::<Result<_, _>>()?;
    let chain = libveritas::cert::CertificateChain::new(sname, certs);
    Ok(chain.to_bytes())
}

#[uniffi::export]
pub fn verify_default() -> u32 {
    libveritas::VERIFY_DEFAULT
}

#[uniffi::export]
pub fn verify_dev_mode() -> u32 {
    libveritas::VERIFY_DEV_MODE
}

#[uniffi::export]
pub fn verify_enable_snark() -> u32 {
    libveritas::VERIFY_ENABLE_SNARK
}

#[uniffi::export]
pub fn sig_primary_zone() -> u8 {
    sip7::SIG_PRIMARY_ZONE
}

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
pub fn verify_spaces_message(
    msg: Vec<u8>,
    signature: Vec<u8>,
    pubkey: Vec<u8>,
) -> Result<(), VeritasError> {
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| VeritasError::InvalidInput {
            msg: "signature must be 64 bytes".to_string(),
        })?;
    let pk: [u8; 32] = pubkey.try_into().map_err(|_| VeritasError::InvalidInput {
        msg: "pubkey must be 32 bytes".to_string(),
    })?;
    libveritas::verify_spaces_message(&msg, &sig, &pk)
        .map_err(|e| VeritasError::VerificationFailed { msg: e.to_string() })
}

/// Verify a raw Schnorr signature (no prefix, caller provides the 32-byte message hash).
///
/// - `msg_hash`: 32-byte SHA256 hash
/// - `signature`: 64-byte Schnorr signature
/// - `pubkey`: 32-byte x-only public key
#[uniffi::export]
pub fn verify_schnorr(
    msg_hash: Vec<u8>,
    signature: Vec<u8>,
    pubkey: Vec<u8>,
) -> Result<(), VeritasError> {
    let hash: [u8; 32] = msg_hash
        .try_into()
        .map_err(|_| VeritasError::InvalidInput {
            msg: "msg_hash must be 32 bytes".to_string(),
        })?;
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| VeritasError::InvalidInput {
            msg: "signature must be 64 bytes".to_string(),
        })?;
    let pk: [u8; 32] = pubkey.try_into().map_err(|_| VeritasError::InvalidInput {
        msg: "pubkey must be 32 bytes".to_string(),
    })?;
    libveritas::verify_schnorr(&hash, &sig, &pk)
        .map_err(|e| VeritasError::VerificationFailed { msg: e.to_string() })
}

/// Decode stored zone bytes to a Zone record.
#[uniffi::export]
pub fn decode_zone(bytes: Vec<u8>) -> Result<Zone, VeritasError> {
    let zone = libveritas::Zone::from_slice(&bytes).map_err(|e| VeritasError::InvalidInput {
        msg: format!("invalid zone: {e}"),
    })?;
    Ok(zone_from_inner(&zone))
}

/// Serialize a Zone record to bytes for storage.
#[uniffi::export]
pub fn zone_to_bytes(zone: Zone) -> Result<Vec<u8>, VeritasError> {
    let inner = zone_to_inner(&zone)?;
    Ok(inner.to_bytes())
}

/// Serialize a Zone record to JSON.
#[uniffi::export]
pub fn zone_to_json(zone: Zone) -> Result<String, VeritasError> {
    let inner = zone_to_inner(&zone)?;
    serde_json::to_string(&inner).map_err(|e| VeritasError::InvalidInput { msg: e.to_string() })
}

/// Compare two zones — returns true if `a` is fresher/better than `b`.
#[uniffi::export]
pub fn zone_is_better_than(a: Zone, b: Zone) -> Result<bool, VeritasError> {
    let inner_a = zone_to_inner(&a)?;
    let inner_b = zone_to_inner(&b)?;
    inner_a
        .is_better_than(&inner_b)
        .map_err(|e| VeritasError::InvalidInput { msg: e.to_string() })
}

/// Decode stored certificate bytes to JSON.
#[uniffi::export]
pub fn decode_certificate(bytes: Vec<u8>) -> Result<String, VeritasError> {
    let cert = libveritas::cert::Certificate::from_slice(&bytes).map_err(|e| {
        VeritasError::InvalidInput {
            msg: format!("invalid certificate: {e}"),
        }
    })?;
    serde_json::to_string(&cert).map_err(|e| VeritasError::InvalidInput { msg: e.to_string() })
}
