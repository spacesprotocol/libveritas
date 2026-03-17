use std::str::FromStr;
use wasm_bindgen::prelude::*;

use libveritas::builder;
use libveritas::msg;
use libveritas::sname::SName;
use serde::Serialize;
use spaces_nums::RootAnchor;

/// Serialize through JSON to get human-readable serde output
/// (hex hashes, string names, etc.) as a native JS object.
fn to_js<T: Serialize>(val: &T) -> Result<JsValue, JsError> {
    let json = serde_json::to_string(val).map_err(|e| JsError::new(&e.to_string()))?;
    js_sys::JSON::parse(&json).map_err(|_| JsError::new("json parse failed"))
}

/// Extract an optional Uint8Array field from a JS object.
fn get_optional_bytes(obj: &JsValue, key: &str) -> Option<Vec<u8>> {
    let val = js_sys::Reflect::get(obj, &key.into()).ok()?;
    if val.is_undefined() || val.is_null() {
        return None;
    }
    Some(js_sys::Uint8Array::from(val).to_vec())
}

/// Parse a JS object into a DataUpdateRequest (name + records, no cert).
fn parse_data_update(entry: &JsValue) -> Result<builder::DataUpdateRequest, JsError> {
    let name = js_sys::Reflect::get(entry, &"name".into())
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| JsError::new("name is required and must be a string"))?;

    let handle = SName::from_str(&name)
        .map_err(|e| JsError::new(&format!("invalid name '{}': {}", name, e)))?;

    let records = get_optional_bytes(entry, "records")
        .map(|b| msg::OffchainRecords::from_slice(&b))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid records: {e}")))?;

    let delegate_records = get_optional_bytes(entry, "delegateRecords")
        .map(|b| msg::OffchainRecords::from_slice(&b))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid delegate_records: {e}")))?;

    Ok(builder::DataUpdateRequest {
        handle,
        records,
        delegate_records,
    })
}

/// Parse a JS object into an UpdateRequest (name + offchain data + optional cert).
fn parse_update_entry(entry: &JsValue) -> Result<builder::UpdateRequest, JsError> {
    let data = parse_data_update(entry)?;
    let cert = get_optional_bytes(entry, "cert")
        .map(|b| libveritas::cert::Certificate::from_slice(&b))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid cert: {e}")))?;

    Ok(builder::UpdateRequest { data, cert })
}

/// Parse a JS array of UpdateRequests (for MessageBuilder).
fn parse_update_entries(updates: &JsValue) -> Result<Vec<builder::UpdateRequest>, JsError> {
    let array = js_sys::Array::from(updates);
    let mut reqs = Vec::with_capacity(array.length() as usize);
    for i in 0..array.length() {
        reqs.push(parse_update_entry(&array.get(i))?);
    }
    Ok(reqs)
}

/// Parse a JS array of DataUpdateRequests (for Message.update).
fn parse_data_updates(updates: &JsValue) -> Result<Vec<builder::DataUpdateRequest>, JsError> {
    let array = js_sys::Array::from(updates);
    let mut reqs = Vec::with_capacity(array.length() as usize);
    for i in 0..array.length() {
        reqs.push(parse_data_update(&array.get(i))?);
    }
    Ok(reqs)
}

#[wasm_bindgen]
pub struct QueryContext {
    inner: msg::QueryContext,
}

#[wasm_bindgen]
impl QueryContext {
    #[wasm_bindgen(constructor)]
    pub fn new() -> QueryContext {
        QueryContext {
            inner: msg::QueryContext::new(),
        }
    }

    /// Add a handle to verify (e.g. "alice@bitcoin").
    /// If no requests are added, all handles in the message are verified.
    pub fn add_request(&mut self, handle: &str) -> Result<(), JsError> {
        let sname = SName::from_str(handle)
            .map_err(|e| JsError::new(&format!("invalid handle: {e}")))?;
        self.inner.add_request(sname);
        Ok(())
    }

    /// Add a known zone from stored bytes (from a previous verification).
    pub fn add_zone(&mut self, zone_bytes: &[u8]) -> Result<(), JsError> {
        let zone = libveritas::Zone::from_slice(zone_bytes)
            .map_err(|e| JsError::new(&format!("invalid zone: {e}")))?;
        self.inner.add_zone(zone);
        Ok(())
    }
}

#[wasm_bindgen]
pub struct Zone {
    inner: libveritas::Zone,
}

#[wasm_bindgen]
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

    pub fn alias(&self) -> Option<String> {
        self.inner.alias.as_ref().map(|a| a.to_string())
    }

    pub fn is_better_than(&self, other: &Zone) -> Result<bool, JsError> {
        self.inner
            .is_better_than(&other.inner)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Returns the full zone as a JS object.
    pub fn to_json(&self) -> Result<JsValue, JsError> {
        to_js(&self.inner)
    }
}

/// A message containing chain proofs and handle data.
#[wasm_bindgen]
pub struct Message {
    inner: msg::Message,
}

#[wasm_bindgen]
impl Message {
    /// Decode a message from borsh bytes.
    #[wasm_bindgen(constructor)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, JsError> {
        let inner = msg::Message::from_slice(bytes)
            .map_err(|e| JsError::new(&format!("invalid message: {e}")))?;
        Ok(Message { inner })
    }

    /// Serialize the message to borsh bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Update records on this message.
    ///
    /// Accepts a JS array of data update entries:
    /// ```js
    /// msg.update([
    ///   { name: "alice@bitcoin", records: Uint8Array },
    ///   { name: "@bitcoin", delegateRecords: Uint8Array }
    /// ])
    /// ```
    ///
    /// To update certificates, construct a new message instead.
    pub fn update(&mut self, updates: JsValue) -> Result<(), JsError> {
        let reqs = parse_data_updates(&updates)?;
        self.inner.update(reqs);
        Ok(())
    }
}

/// Builder for constructing messages from update requests and chain proofs.
#[wasm_bindgen]
pub struct MessageBuilder {
    inner: Option<builder::MessageBuilder>,
}

#[wasm_bindgen]
impl MessageBuilder {
    /// Create a builder from a JS array of update requests.
    ///
    /// ```js
    /// let builder = new MessageBuilder([
    ///   { name: "@bitcoin", records: Uint8Array, cert: Uint8Array },
    ///   { name: "alice@bitcoin", records: Uint8Array, cert: Uint8Array }
    /// ])
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new(requests: JsValue) -> Result<MessageBuilder, JsError> {
        let reqs = parse_update_entries(&requests)?;
        Ok(MessageBuilder {
            inner: Some(builder::MessageBuilder::new(reqs)),
        })
    }

    /// Returns the chain proof request as a JS object.
    ///
    /// Send this to the provider/fabric to get the chain proofs needed for `build()`.
    pub fn chain_proof_request(&self) -> Result<JsValue, JsError> {
        let builder = self
            .inner
            .as_ref()
            .ok_or_else(|| JsError::new("builder already consumed by build()"))?;
        to_js(&builder.chain_proof_request())
    }

    /// Build the message from a borsh-encoded ChainProof.
    ///
    /// Consumes the builder — cannot be called twice.
    pub fn build(&mut self, chain_proof: &[u8]) -> Result<Message, JsError> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("builder already consumed by build()"))?;
        let chain = msg::ChainProof::from_slice(chain_proof)
            .map_err(|e| JsError::new(&format!("invalid chain proof: {e}")))?;
        let msg = builder
            .build(chain)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Message { inner: msg })
    }
}

#[wasm_bindgen]
pub struct Veritas {
    inner: libveritas::Veritas,
}

#[wasm_bindgen]
impl Veritas {
    #[wasm_bindgen(constructor)]
    pub fn new(anchors: JsValue) -> Result<Veritas, JsError> {
        let anchors: Vec<RootAnchor> = serde_wasm_bindgen::from_value(anchors)
            .map_err(|e| JsError::new(&format!("invalid anchors: {e}")))?;
        let inner = libveritas::Veritas::new()
            .with_anchors(anchors)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Veritas { inner })
    }

    #[wasm_bindgen(js_name = "withDevMode")]
    pub fn with_dev_mode(anchors: JsValue) -> Result<Veritas, JsError> {
        let anchors: Vec<RootAnchor> = serde_wasm_bindgen::from_value(anchors)
            .map_err(|e| JsError::new(&format!("invalid anchors: {e}")))?;
        let inner = libveritas::Veritas::new()
            .with_anchors(anchors)
            .map_err(|e| JsError::new(&e.to_string()))?
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
    ) -> Result<VerifiedMessage, JsError> {
        let inner = self
            .inner
            .verify_message(&ctx.inner, msg.inner.clone())
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(VerifiedMessage { inner })
    }
}

/// Result of verifying a message.
#[wasm_bindgen]
pub struct VerifiedMessage {
    inner: libveritas::VerifiedMessage,
}

#[wasm_bindgen]
impl VerifiedMessage {
    /// All verified zones.
    pub fn zones(&self) -> Vec<Zone> {
        self.inner
            .zones
            .iter()
            .map(|z| Zone { inner: z.clone() })
            .collect()
    }

    /// Get certificate for a specific handle (e.g. "alice@bitcoin").
    /// Returns null if the handle was not verified.
    pub fn certificate(&self, handle: &str) -> Result<JsValue, JsError> {
        let sname = SName::from_str(handle)
            .map_err(|e| JsError::new(&format!("invalid handle: {e}")))?;
        match self.inner.certificate(&sname) {
            Some(cert) => to_js(&cert),
            None => Ok(JsValue::NULL),
        }
    }

    /// All certificates as a JS array.
    pub fn certificates(&self) -> Result<JsValue, JsError> {
        let certs: Vec<_> = self.inner.certificates().collect();
        to_js(&certs)
    }

    /// Get the verified message for rebroadcasting or updating.
    pub fn message(&self) -> Message {
        Message {
            inner: self.inner.message.clone(),
        }
    }

    /// Get the verified message as borsh bytes.
    pub fn message_bytes(&self) -> Vec<u8> {
        self.inner.message.to_bytes()
    }
}

// ── Record / RecordSet ────────────────────────────────────────────

fn parse_js_record(obj: &JsValue) -> Result<sip7::Record, JsError> {
    let rtype = js_sys::Reflect::get(obj, &"type".into())
        .ok().and_then(|v| v.as_string())
        .ok_or_else(|| JsError::new("record must have a 'type' field"))?;
    match rtype.as_str() {
        "seq" => {
            let version = js_sys::Reflect::get(obj, &"version".into())
                .ok().and_then(|v| v.as_f64())
                .ok_or_else(|| JsError::new("seq record: 'version' must be a number"))? as u64;
            Ok(sip7::Record::seq(version))
        }
        "txt" => {
            let key = js_sys::Reflect::get(obj, &"key".into())
                .ok().and_then(|v| v.as_string())
                .ok_or_else(|| JsError::new("txt record: 'key' must be a string"))?;
            let value = js_sys::Reflect::get(obj, &"value".into())
                .ok().and_then(|v| v.as_string())
                .ok_or_else(|| JsError::new("txt record: 'value' must be a string"))?;
            Ok(sip7::Record::txt(&key, &value))
        }
        "blob" => {
            let key = js_sys::Reflect::get(obj, &"key".into())
                .ok().and_then(|v| v.as_string())
                .ok_or_else(|| JsError::new("blob record: 'key' must be a string"))?;
            let value = js_sys::Reflect::get(obj, &"value".into())
                .map(|v| js_sys::Uint8Array::from(v).to_vec())
                .map_err(|_| JsError::new("blob record: 'value' must be a Uint8Array"))?;
            Ok(sip7::Record::blob(&key, value))
        }
        "unknown" => {
            let rt = js_sys::Reflect::get(obj, &"rtype".into())
                .ok().and_then(|v| v.as_f64())
                .ok_or_else(|| JsError::new("unknown record: 'rtype' must be a number"))? as u8;
            let rdata = js_sys::Reflect::get(obj, &"rdata".into())
                .map(|v| js_sys::Uint8Array::from(v).to_vec())
                .map_err(|_| JsError::new("unknown record: 'rdata' must be a Uint8Array"))?;
            Ok(sip7::Record::unknown(rt, rdata))
        }
        other => Err(JsError::new(&format!("unknown record type: {other}"))),
    }
}

fn sip7_record_to_js(record: &sip7::Record) -> JsValue {
    match record {
        sip7::Record::Seq(version) => Record::seq(*version),
        sip7::Record::Txt { key, value } => Record::txt(key, value),
        sip7::Record::Blob { key, value } => Record::blob(key, value),
        sip7::Record::Unknown { rtype, rdata } => Record::unknown(*rtype, rdata),
    }
}

/// Record constructors for building a RecordSet.
///
/// ```js
/// const rs = RecordSet.pack([
///     Record.txt("btc", "bc1qtest"),
///     Record.blob("avatar", pngBytes),
///     Record.unknown(0x10, raw),
/// ]);
/// ```
#[wasm_bindgen]
pub struct Record;

#[wasm_bindgen]
impl Record {
    pub fn seq(version: u64) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"seq".into()).unwrap();
        js_sys::Reflect::set(&obj, &"version".into(), &version.into()).unwrap();
        obj.into()
    }

    pub fn txt(key: &str, value: &str) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"txt".into()).unwrap();
        js_sys::Reflect::set(&obj, &"key".into(), &key.into()).unwrap();
        js_sys::Reflect::set(&obj, &"value".into(), &value.into()).unwrap();
        obj.into()
    }

    pub fn blob(key: &str, value: &[u8]) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"blob".into()).unwrap();
        js_sys::Reflect::set(&obj, &"key".into(), &key.into()).unwrap();
        js_sys::Reflect::set(&obj, &"value".into(), &js_sys::Uint8Array::from(value)).unwrap();
        obj.into()
    }

    pub fn unknown(rtype: u8, rdata: &[u8]) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"unknown".into()).unwrap();
        js_sys::Reflect::set(&obj, &"rtype".into(), &rtype.into()).unwrap();
        js_sys::Reflect::set(&obj, &"rdata".into(), &js_sys::Uint8Array::from(rdata)).unwrap();
        obj.into()
    }
}

/// SIP-7 record set — wire-format encoded records.
///
/// ```js
/// // Pack from records
/// const rs = RecordSet.pack([Record.txt("btc", "bc1qtest")]);
/// const wire = rs.toBytes();
///
/// // Load from wire bytes
/// const rs = new RecordSet(wire);
/// for (const r of rs.unpack()) { ... }
/// ```
#[wasm_bindgen]
pub struct RecordSet {
    inner: sip7::RecordSet,
}

#[wasm_bindgen]
impl RecordSet {
    /// Wrap raw wire bytes (lazy — no parsing until unpack).
    #[wasm_bindgen(constructor)]
    pub fn new(data: &[u8]) -> RecordSet {
        RecordSet { inner: sip7::RecordSet::new(data.to_vec()) }
    }

    /// Pack records into wire format.
    pub fn pack(records: JsValue) -> Result<RecordSet, JsError> {
        let array = js_sys::Array::from(&records);
        let mut sip_records = Vec::with_capacity(array.length() as usize);
        for i in 0..array.length() {
            sip_records.push(parse_js_record(&array.get(i))?);
        }
        let inner = sip7::RecordSet::pack(sip_records)
            .map_err(|e| JsError::new(&format!("pack failed: {e}")))?;
        Ok(RecordSet { inner })
    }

    /// Raw wire bytes.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_slice().to_vec()
    }

    /// Parse all records.
    pub fn unpack(&self) -> Result<JsValue, JsError> {
        let records = self.inner.unpack()
            .map_err(|e| JsError::new(&format!("unpack failed: {e}")))?;
        let array = js_sys::Array::new();
        for record in records {
            array.push(&sip7_record_to_js(&record));
        }
        Ok(array.into())
    }

    #[wasm_bindgen(js_name = "isEmpty")]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The 32-byte signing hash (Spaces signed-message prefix + SHA256).
    #[wasm_bindgen(js_name = "signingId")]
    pub fn signing_id(&self) -> Vec<u8> {
        let msg = libveritas::hash_signable_message(self.inner.as_slice());
        msg.as_ref().to_vec()
    }
}

/// Helpers for constructing OffchainRecords (signed record sets).
///
/// ```js
/// const rs = RecordSet.pack([Record.seq(0), Record.txt("btc", "bc1qtest")]);
/// const sig = await wallet.signSchnorr(rs.signingId());
/// const bytes = OffchainRecords.from(rs, sig);
/// ```
#[wasm_bindgen]
pub struct OffchainRecords;

#[wasm_bindgen]
impl OffchainRecords {
    /// Create borsh-encoded OffchainRecords from a RecordSet and 64-byte signature.
    pub fn from(record_set: &RecordSet, signature: &[u8]) -> Result<Vec<u8>, JsError> {
        let sig: [u8; 64] = signature.try_into()
            .map_err(|_| JsError::new("signature must be 64 bytes"))?;
        let offchain = msg::OffchainRecords::new(
            record_set.inner.clone(),
            libveritas::cert::Signature(sig),
        );
        Ok(offchain.to_bytes())
    }
}

/// Hash a message with the Spaces signed-message prefix (SHA256).
/// Returns the 32-byte digest suitable for Schnorr signing/verification.
#[wasm_bindgen]
pub fn hash_signable_message(msg: &[u8]) -> Vec<u8> {
    let secp_msg = libveritas::hash_signable_message(msg);
    secp_msg.as_ref().to_vec()
}

/// Verify a Schnorr signature over a message using the Spaces signed-message prefix.
#[wasm_bindgen]
pub fn verify_spaces_message(msg: &[u8], signature: &[u8], pubkey: &[u8]) -> Result<(), JsError> {
    let sig: [u8; 64] = signature.try_into()
        .map_err(|_| JsError::new("signature must be 64 bytes"))?;
    let pk: [u8; 32] = pubkey.try_into()
        .map_err(|_| JsError::new("pubkey must be 32 bytes"))?;
    libveritas::verify_spaces_message(msg, &sig, &pk)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Verify a raw Schnorr signature (no prefix, caller provides the 32-byte message hash).
#[wasm_bindgen]
pub fn verify_schnorr(msg_hash: &[u8], signature: &[u8], pubkey: &[u8]) -> Result<(), JsError> {
    let hash: [u8; 32] = msg_hash.try_into()
        .map_err(|_| JsError::new("msg_hash must be 32 bytes"))?;
    let sig: [u8; 64] = signature.try_into()
        .map_err(|_| JsError::new("signature must be 64 bytes"))?;
    let pk: [u8; 32] = pubkey.try_into()
        .map_err(|_| JsError::new("pubkey must be 32 bytes"))?;
    libveritas::verify_schnorr(&hash, &sig, &pk)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Decode stored zone bytes to a Zone object.
#[wasm_bindgen]
pub fn decode_zone(bytes: &[u8]) -> Result<Zone, JsError> {
    let zone = libveritas::Zone::from_slice(bytes)
        .map_err(|e| JsError::new(&format!("invalid zone: {e}")))?;
    Ok(Zone { inner: zone })
}

/// Decode stored certificate bytes to a JS object.
#[wasm_bindgen]
pub fn decode_certificate(bytes: &[u8]) -> Result<JsValue, JsError> {
    let cert = libveritas::cert::Certificate::from_slice(bytes)
        .map_err(|e| JsError::new(&format!("invalid certificate: {e}")))?;
    to_js(&cert)
}
