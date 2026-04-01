use std::str::FromStr;
use wasm_bindgen::prelude::*;

use libveritas::builder;
use libveritas::msg;
use libveritas::spaces_protocol::sname::SName;
use serde::Serialize;
use spaces_nums::RootAnchor;

#[wasm_bindgen(js_name = "VERIFY_DEFAULT")]
pub fn verify_default() -> u32 { libveritas::VERIFY_DEFAULT }

#[wasm_bindgen(js_name = "VERIFY_DEV_MODE")]
pub fn verify_dev_mode() -> u32 { libveritas::VERIFY_DEV_MODE }

#[wasm_bindgen(js_name = "VERIFY_ENABLE_SNARK")]
pub fn verify_enable_snark() -> u32 { libveritas::VERIFY_ENABLE_SNARK }

#[wasm_bindgen(js_name = "SIG_PRIMARY_ZONE")]
pub fn sig_primary_zone() -> u8 { sip7::SIG_PRIMARY_ZONE }

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
        .map(sip7::RecordSet::new);

    let delegate_records = get_optional_bytes(entry, "delegateRecords")
        .map(sip7::RecordSet::new);

    Ok(builder::DataUpdateRequest {
        handle,
        records,
        delegate_records,
    })
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
    #[wasm_bindgen(js_name = "addRequest")]
    pub fn add_request(&mut self, handle: &str) -> Result<(), JsError> {
        let sname = SName::from_str(handle)
            .map_err(|e| JsError::new(&format!("invalid handle: {e}")))?;
        self.inner.add_request(sname);
        Ok(())
    }

    /// Add a known zone from stored bytes (from a previous verification).
    #[wasm_bindgen(js_name = "addZone")]
    pub fn add_zone(&mut self, zone_bytes: &[u8]) -> Result<(), JsError> {
        let zone = libveritas::Zone::from_slice(zone_bytes)
            .map_err(|e| JsError::new(&format!("invalid zone: {e}")))?;
        self.inner.add_zone(zone);
        Ok(())
    }
}

// -- Zone conversions (serde-based, matches Rust/Swift format exactly) --

fn zone_to_js(z: &libveritas::Zone) -> Result<JsValue, JsError> {
    to_js(z)
}

fn trust_set_to_js(ts: &libveritas::TrustSet) -> Result<JsValue, JsError> {
    let obj = js_sys::Object::new();
    let id = js_sys::Uint8Array::new_with_length(32);
    id.copy_from(&ts.id);
    js_sys::Reflect::set(&obj, &"id".into(), &id).map_err(|_| JsError::new("failed to set id"))?;
    let roots = js_sys::Array::new();
    for r in &ts.roots {
        let arr = js_sys::Uint8Array::new_with_length(32);
        arr.copy_from(r);
        roots.push(&arr);
    }
    js_sys::Reflect::set(&obj, &"roots".into(), &roots).map_err(|_| JsError::new("failed to set roots"))?;
    Ok(obj.into())
}

fn zone_from_js(val: &JsValue) -> Result<libveritas::Zone, JsError> {
    let json = js_sys::JSON::stringify(val)
        .map_err(|_| JsError::new("failed to stringify zone"))?;
    let json_str = json.as_string()
        .ok_or_else(|| JsError::new("stringify returned non-string"))?;
    serde_json::from_str(&json_str)
        .map_err(|e| JsError::new(&format!("invalid zone: {e}")))
}

/// A message containing chain proofs and handle data.
#[wasm_bindgen]
pub struct Message {
    inner: msg::Message,
}

#[wasm_bindgen]
impl Message {
    /// Decode a message from bytes.
    #[wasm_bindgen(constructor)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, JsError> {
        let inner = msg::Message::from_slice(bytes)
            .map_err(|e| JsError::new(&format!("invalid message: {e}")))?;
        Ok(Message { inner })
    }

    /// Serialize the message to bytes.
    #[wasm_bindgen(js_name = "toBytes")]
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

    /// Set records on the message for a canonical name.
    #[wasm_bindgen(js_name = "setRecords")]
    pub fn set_records(&mut self, canonical: &str, records_bytes: &[u8]) -> Result<(), JsError> {
        let sname = SName::from_str(canonical)
            .map_err(|e| JsError::new(&format!("invalid canonical: {e}")))?;
        self.inner.set_records(&sname, sip7::RecordSet::new(records_bytes.to_vec()));
        Ok(())
    }

    /// Set delegate records on the message for a canonical name.
    #[wasm_bindgen(js_name = "setDelegateRecords")]
    pub fn set_delegate_records(&mut self, canonical: &str, records_bytes: &[u8]) -> Result<(), JsError> {
        let sname = SName::from_str(canonical)
            .map_err(|e| JsError::new(&format!("invalid canonical: {e}")))?;
        self.inner.set_delegate_records(&sname, sip7::RecordSet::new(records_bytes.to_vec()));
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
    /// Create an empty builder.
    ///
    /// ```js
    /// let builder = new MessageBuilder()
    /// builder.addChain(chainBytes)
    /// builder.addRecords("alice@bitcoin", recordsBytes)
    /// ```
    #[wasm_bindgen(constructor)]
    pub fn new() -> MessageBuilder {
        MessageBuilder {
            inner: Some(builder::MessageBuilder::new()),
        }
    }

    fn inner_mut(&mut self) -> Result<&mut builder::MessageBuilder, JsError> {
        self.inner.as_mut()
            .ok_or_else(|| JsError::new("builder already consumed by build()"))
    }

    /// Add a .spacecert chain with records (sip7 wire bytes).
    #[wasm_bindgen(js_name = "addHandle")]
    pub fn add_handle(&mut self, chain_bytes: &[u8], records_bytes: &[u8]) -> Result<(), JsError> {
        let chain = libveritas::cert::CertificateChain::from_slice(chain_bytes)
            .map_err(|e| JsError::new(&format!("invalid chain: {e}")))?;
        let records = sip7::RecordSet::new(records_bytes.to_vec());
        self.inner_mut()?.add_handle(chain, records);
        Ok(())
    }

    /// Add all certificates from a .spacecert chain.
    #[wasm_bindgen(js_name = "addChain")]
    pub fn add_chain(&mut self, chain_bytes: &[u8]) -> Result<(), JsError> {
        let chain = libveritas::cert::CertificateChain::from_slice(chain_bytes)
            .map_err(|e| JsError::new(&format!("invalid chain: {e}")))?;
        self.inner_mut()?.add_chain(chain);
        Ok(())
    }

    /// Add a single certificate.
    #[wasm_bindgen(js_name = "addCert")]
    pub fn add_cert(&mut self, cert_bytes: &[u8]) -> Result<(), JsError> {
        let cert = libveritas::cert::Certificate::from_slice(cert_bytes)
            .map_err(|e| JsError::new(&format!("invalid cert: {e}")))?;
        self.inner_mut()?.add_cert(cert);
        Ok(())
    }

    /// Add records for a handle (sip7 wire bytes).
    #[wasm_bindgen(js_name = "addRecords")]
    pub fn add_records(&mut self, handle: &str, records_bytes: &[u8]) -> Result<(), JsError> {
        let sname = SName::from_str(handle)
            .map_err(|e| JsError::new(&format!("invalid handle: {e}")))?;
        let records = sip7::RecordSet::new(records_bytes.to_vec());
        self.inner_mut()?.add_records(sname, records);
        Ok(())
    }

    /// Add a full data update (records + optional delegate records).
    #[wasm_bindgen(js_name = "addUpdate")]
    pub fn add_update(&mut self, entry: JsValue) -> Result<(), JsError> {
        let update = parse_data_update(&entry)?;
        self.inner_mut()?.add_update(update);
        Ok(())
    }

    /// Returns the chain proof request as a JS object.
    ///
    /// Send this to the provider/fabric to get the chain proofs needed for `build()`.
    #[wasm_bindgen(js_name = "chainProofRequest")]
    pub fn chain_proof_request(&self) -> Result<JsValue, JsError> {
        let builder = self
            .inner
            .as_ref()
            .ok_or_else(|| JsError::new("builder already consumed by build()"))?;
        to_js(&builder.chain_proof_request())
    }

    /// Build the message from a ChainProof.
    ///
    /// Consumes the builder — cannot be called twice.
    /// Returns `{ message, unsigned }` with unsigned record sets that need signing.
    pub fn build(&mut self, chain_proof: &[u8]) -> Result<JsValue, JsError> {
        let builder = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("builder already consumed by build()"))?;
        let chain = msg::ChainProof::from_slice(chain_proof)
            .map_err(|e| JsError::new(&format!("invalid chain proof: {e}")))?;
        let (inner_msg, unsigned) = builder
            .build(chain)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let unsigned_arr = js_sys::Array::new();
        for u in unsigned {
            let obj: UnsignedRecordSet = UnsignedRecordSet { inner: u };
            unsigned_arr.push(&obj.into());
        }

        let result = js_sys::Object::new();
        let message = Message { inner: inner_msg };
        js_sys::Reflect::set(&result, &"message".into(), &message.into()).unwrap();
        js_sys::Reflect::set(&result, &"unsigned".into(), &unsigned_arr).unwrap();
        Ok(result.into())
    }
}

/// An unsigned record set pending signature.
#[wasm_bindgen]
pub struct UnsignedRecordSet {
    inner: msg::UnsignedRecordSet,
}

#[wasm_bindgen]
impl UnsignedRecordSet {
    /// The original handle name (before flattening).
    pub fn handle(&self) -> String {
        self.inner.handle.to_string()
    }

    /// The canonical/flattened name.
    pub fn canonical(&self) -> String {
        self.inner.canonical.to_string()
    }

    /// Whether these are delegate records.
    #[wasm_bindgen(js_name = "isDelegate")]
    pub fn is_delegate(&self) -> bool {
        self.inner.delegate
    }

    /// Current sig flags.
    pub fn flags(&self) -> u8 {
        self.inner.flags
    }

    /// Set sig flags (e.g. `SIG_PRIMARY_ZONE`).
    #[wasm_bindgen(js_name = "setFlags")]
    pub fn set_flags(&mut self, flags: u8) {
        self.inner.flags = flags;
    }

    /// The raw signable bytes (before hashing). Use when the signer doesn't take a digest.
    #[wasm_bindgen(js_name = "signableBytes")]
    pub fn signable_bytes(&self) -> Vec<u8> {
        self.inner.signable_bytes()
    }

    /// The 32-byte signing hash (Spaces signed-message prefix + SHA256).
    #[wasm_bindgen(js_name = "signingId")]
    pub fn signing_id(&self) -> Vec<u8> {
        self.inner.signing_id().to_vec()
    }

    /// Pack the Sig record with the given signature. Returns signed RecordSet wire bytes.
    #[wasm_bindgen(js_name = "packSig")]
    pub fn pack_sig(&self, signature: &[u8]) -> Vec<u8> {
        self.inner.pack_sig(signature.to_vec()).as_slice().to_vec()
    }
}

#[wasm_bindgen]
pub struct Anchors {
    inner: Vec<RootAnchor>,
}

#[wasm_bindgen]
impl Anchors {
    #[wasm_bindgen(constructor)]
    pub fn from_json(json: &str) -> Result<Anchors, JsError> {
        let inner: Vec<RootAnchor> = serde_json::from_str(json)
            .map_err(|e| JsError::new(&format!("invalid anchors: {e}")))?;
        Ok(Anchors { inner })
    }

    #[wasm_bindgen(js_name = "computeTrustSet")]
    pub fn compute_trust_set(&self) -> Result<JsValue, JsError> {
        let ts = libveritas::compute_trust_set(&self.inner);
        trust_set_to_js(&ts)
    }
}

#[wasm_bindgen]
pub struct Veritas {
    inner: libveritas::Veritas,
}

#[wasm_bindgen]
impl Veritas {
    #[wasm_bindgen(constructor)]
    pub fn new(anchors: &Anchors) -> Result<Veritas, JsError> {
        let inner = libveritas::Veritas::new()
            .with_anchors(anchors.inner.clone())
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Veritas { inner })
    }

    #[wasm_bindgen(js_name = "oldestAnchor")]
    pub fn oldest_anchor(&self) -> u32 {
        self.inner.oldest_anchor()
    }

    #[wasm_bindgen(js_name = "newestAnchor")]
    pub fn newest_anchor(&self) -> u32 {
        self.inner.newest_anchor()
    }

    #[wasm_bindgen(js_name = "computeTrustSet")]
    pub fn compute_trust_set(&self) -> Result<JsValue, JsError> {
        let ts = self.inner.compute_trust_set();
        trust_set_to_js(&ts)
    }

    #[wasm_bindgen(js_name = "isFinalized")]
    pub fn is_finalized(&self, commitment_height: u32) -> bool {
        self.inner.is_finalized(commitment_height)
    }

    #[wasm_bindgen(js_name = "sovereigntyFor")]
    pub fn sovereignty_for(&self, commitment_height: u32) -> String {
        self.inner.sovereignty_for(commitment_height).to_string()
    }

    /// Verify a message with default options.
    pub fn verify(
        &self,
        ctx: &QueryContext,
        msg: &Message,
    ) -> Result<VerifiedMessage, JsError> {
        let inner = self
            .inner
            .verify(&ctx.inner, msg.inner.clone())
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(VerifiedMessage { inner })
    }

    /// Verify a message with option flags (combine with bitwise OR).
    #[wasm_bindgen(js_name = "verifyWithOptions")]
    pub fn verify_with_options(
        &self,
        ctx: &QueryContext,
        msg: &Message,
        options: u32,
    ) -> Result<VerifiedMessage, JsError> {
        let inner = self
            .inner
            .verify_with_options(&ctx.inner, msg.inner.clone(), options)
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
    /// The root id this message was verified against.
    #[wasm_bindgen(js_name = "rootId")]
    pub fn root_id(&self) -> Vec<u8> {
        self.inner.root_id.to_vec()
    }

    /// All verified zones as plain JS objects.
    pub fn zones(&self) -> Result<JsValue, JsError> {
        let array = js_sys::Array::new();
        for z in &self.inner.zones {
            array.push(&zone_to_js(z)?);
        }
        Ok(array.into())
    }

    /// All certificates as serialized byte arrays.
    pub fn certificates(&self) -> Vec<js_sys::Uint8Array> {
        self.inner.certificates().map(|c| {
            let bytes = c.to_bytes();
            let arr = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
            arr.copy_from(&bytes);
            arr
        }).collect()
    }

    /// Get the verified message for rebroadcasting or updating.
    pub fn message(&self) -> Message {
        Message {
            inner: self.inner.message.clone(),
        }
    }

    /// Get the verified message as bytes.
    #[wasm_bindgen(js_name = "messageBytes")]
    pub fn message_bytes(&self) -> Vec<u8> {
        self.inner.message.to_bytes()
    }
}

/// Batched iterative resolver for nested handle names.
#[wasm_bindgen]
pub struct Lookup {
    inner: libveritas::names::Lookup,
}

#[wasm_bindgen]
impl Lookup {
    /// Create a lookup from an array of handle name strings.
    #[wasm_bindgen(constructor)]
    pub fn new(names: Vec<String>) -> Result<Lookup, JsError> {
        let snames: Vec<SName> = names.iter()
            .map(|n| SName::from_str(n).map_err(|e| JsError::new(&format!("invalid name '{}': {}", n, e))))
            .collect::<Result<_, _>>()?;
        Ok(Lookup { inner: libveritas::names::Lookup::new(snames) })
    }

    /// Returns the first batch of handles to look up.
    pub fn start(&self) -> Vec<String> {
        self.inner.start().iter().map(|s| s.to_string()).collect()
    }

    /// Feed zones from a resolveAll response.
    /// Returns the next batch of handles to look up (empty = done).
    pub fn advance(&self, zones: JsValue) -> Result<Vec<String>, JsError> {
        let array = js_sys::Array::from(&zones);
        let inner_zones: Vec<libveritas::Zone> = (0..array.length())
            .map(|i| zone_from_js(&array.get(i)))
            .collect::<Result<_, _>>()?;
        Ok(self.inner.advance(&inner_zones).iter().map(|s| s.to_string()).collect())
    }

    /// Expand zone handles using the alias map accumulated during resolution.
    #[wasm_bindgen(js_name = "expandZones")]
    pub fn expand_zones(&self, zones: JsValue) -> Result<JsValue, JsError> {
        let array = js_sys::Array::from(&zones);
        let mut inner_zones: Vec<libveritas::Zone> = (0..array.length())
            .map(|i| zone_from_js(&array.get(i)))
            .collect::<Result<_, _>>()?;
        self.inner.expand_zones(&mut inner_zones);
        let result = js_sys::Array::new();
        for z in &inner_zones {
            result.push(&zone_to_js(z)?);
        }
        Ok(result.into())
    }
}

/// Create a .spacecert file from a subject name and certificate bytes.
///
/// Collects certificates from multiple verified messages into a single chain.
#[wasm_bindgen(js_name = "createCertificateChain")]
pub fn create_certificate_chain(subject: &str, cert_bytes_list: Vec<js_sys::Uint8Array>) -> Result<Vec<u8>, JsError> {
    let sname = SName::from_str(subject)
        .map_err(|e| JsError::new(&format!("invalid subject: {e}")))?;
    let certs: Vec<libveritas::cert::Certificate> = cert_bytes_list.iter()
        .map(|b| libveritas::cert::Certificate::from_slice(&b.to_vec())
            .map_err(|e| JsError::new(&format!("invalid cert: {e}"))))
        .collect::<Result<_, _>>()?;
    let chain = libveritas::cert::CertificateChain::new(sname, certs);
    Ok(chain.to_bytes())
}

// ── Record / RecordSet ────────────────────────────────────────────

fn parse_js_record(obj: &JsValue) -> Result<sip7::Record, JsError> {
    let rtype = js_sys::Reflect::get(obj, &"type".into())
        .ok().and_then(|v| v.as_string())
        .ok_or_else(|| JsError::new("record must have a 'type' field"))?;
    match rtype.as_str() {
        "seq" => {
            let raw = js_sys::Reflect::get(obj, &"version".into())
                .map_err(|_| JsError::new("seq record: 'version' is required"))?;
            let version = if let Some(n) = raw.as_f64() {
                n as u64
            } else if raw.is_bigint() {
                u64::try_from(js_sys::BigInt::from(raw))
                    .map_err(|_| JsError::new("seq record: 'version' out of u64 range"))?
            } else {
                return Err(JsError::new("seq record: 'version' must be a number or bigint"));
            };
            Ok(sip7::Record::seq(version))
        }
        "txt" => {
            let key = js_sys::Reflect::get(obj, &"key".into())
                .ok().and_then(|v| v.as_string())
                .ok_or_else(|| JsError::new("txt record: 'key' must be a string"))?;
            let raw = js_sys::Reflect::get(obj, &"value".into())
                .map_err(|_| JsError::new("txt record: 'value' is required"))?;
            let values = if raw.is_string() {
                vec![raw.as_string().unwrap()]
            } else if js_sys::Array::is_array(&raw) {
                let arr = js_sys::Array::from(&raw);
                (0..arr.length())
                    .map(|i| arr.get(i).as_string()
                        .ok_or_else(|| JsError::new("txt record: array values must be strings")))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                return Err(JsError::new("txt record: 'value' must be a string or array of strings"));
            };
            let refs: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
            Ok(sip7::Record::txt(&key, &refs))
        }
        "addr" => {
            let key = js_sys::Reflect::get(obj, &"key".into())
                .ok().and_then(|v| v.as_string())
                .ok_or_else(|| JsError::new("addr record: 'key' must be a string"))?;
            let raw = js_sys::Reflect::get(obj, &"value".into())
                .map_err(|_| JsError::new("addr record: 'value' is required"))?;
            let values = if raw.is_string() {
                vec![raw.as_string().unwrap()]
            } else if js_sys::Array::is_array(&raw) {
                let arr = js_sys::Array::from(&raw);
                (0..arr.length())
                    .map(|i| arr.get(i).as_string()
                        .ok_or_else(|| JsError::new("addr record: array values must be strings")))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                return Err(JsError::new("addr record: 'value' must be a string or array of strings"));
            };
            let refs: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
            Ok(sip7::Record::addr(&key, &refs))
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
        "sig" => {
            let canonical = js_sys::Reflect::get(obj, &"canonical".into())
                .ok().and_then(|v| v.as_string())
                .ok_or_else(|| JsError::new("sig record: 'canonical' must be a string"))?;
            let handle = js_sys::Reflect::get(obj, &"handle".into())
                .ok().and_then(|v| v.as_string())
                .unwrap_or_default();
            let flags = js_sys::Reflect::get(obj, &"flags".into())
                .ok().and_then(|v| v.as_f64())
                .unwrap_or(0.0) as u8;
            let sig = js_sys::Reflect::get(obj, &"sig".into())
                .map(|v| js_sys::Uint8Array::from(v).to_vec())
                .map_err(|_| JsError::new("sig record: 'sig' must be a Uint8Array"))?;
            let canonical = SName::from_str(&canonical)
                .map_err(|e| JsError::new(&format!("sig record: invalid canonical: {e}")))?;
            let handle = if handle.is_empty() {
                SName::empty()
            } else {
                SName::from_str(&handle)
                    .map_err(|e| JsError::new(&format!("sig record: invalid handle: {e}")))?
            };
            Ok(sip7::Record::sig(canonical, handle, sig, flags))
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

fn txt_to_js(key: &str, value: &[String]) -> JsValue {
    let arr = js_sys::Array::new();
    for v in value {
        arr.push(&v.into());
    }
    Record::txt(key, arr.into())
}

fn addr_to_js(key: &str, value: &[String]) -> JsValue {
    let arr = js_sys::Array::new();
    for v in value {
        arr.push(&v.into());
    }
    Record::addr(key, arr.into())
}

fn sip7_record_to_js(record: &sip7::Record) -> JsValue {
    match record {
        sip7::Record::Seq(version) => Record::seq(*version),
        sip7::Record::Txt { key, value } => txt_to_js(key, value),
        sip7::Record::Addr { key, value } => addr_to_js(key, value),
        sip7::Record::Blob { key, value } => Record::blob(key, value),
        sip7::Record::Sig { flags, canonical, handle, sig } => Record::sig(
            &canonical.to_string(),
            &handle.to_string(),
            *flags,
            sig,
        ),
        sip7::Record::Unknown { rtype, rdata } => Record::unknown(*rtype, rdata),
    }
}

/// Record constructors for building a RecordSet.
///
/// ```js
/// const rs = RecordSet.pack([
///     Record.txt("btc", ["bc1qtest"]),
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

    pub fn txt(key: &str, value: JsValue) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"txt".into()).unwrap();
        js_sys::Reflect::set(&obj, &"key".into(), &key.into()).unwrap();
        js_sys::Reflect::set(&obj, &"value".into(), &value).unwrap();
        obj.into()
    }

    pub fn addr(key: &str, value: JsValue) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"addr".into()).unwrap();
        js_sys::Reflect::set(&obj, &"key".into(), &key.into()).unwrap();
        js_sys::Reflect::set(&obj, &"value".into(), &value).unwrap();
        obj.into()
    }

    pub fn blob(key: &str, value: &[u8]) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"blob".into()).unwrap();
        js_sys::Reflect::set(&obj, &"key".into(), &key.into()).unwrap();
        js_sys::Reflect::set(&obj, &"value".into(), &js_sys::Uint8Array::from(value)).unwrap();
        obj.into()
    }

    pub fn sig(canonical: &str, handle: &str, flags: u8, sig: &[u8]) -> JsValue {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"type".into(), &"sig".into()).unwrap();
        js_sys::Reflect::set(&obj, &"canonical".into(), &canonical.into()).unwrap();
        js_sys::Reflect::set(&obj, &"handle".into(), &handle.into()).unwrap();
        js_sys::Reflect::set(&obj, &"flags".into(), &flags.into()).unwrap();
        js_sys::Reflect::set(&obj, &"sig".into(), &js_sys::Uint8Array::from(sig)).unwrap();
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


/// Hash a message with the Spaces signed-message prefix (SHA256).
/// Returns the 32-byte digest suitable for Schnorr signing/verification.
#[wasm_bindgen(js_name = "hashSignableMessage")]
pub fn hash_signable_message(msg: &[u8]) -> Vec<u8> {
    let secp_msg = libveritas::hash_signable_message(msg);
    secp_msg.as_ref().to_vec()
}

/// Verify a Schnorr signature over a message using the Spaces signed-message prefix.
#[wasm_bindgen(js_name = "verifySpacesMessage")]
pub fn verify_spaces_message(msg: &[u8], signature: &[u8], pubkey: &[u8]) -> Result<(), JsError> {
    let sig: [u8; 64] = signature.try_into()
        .map_err(|_| JsError::new("signature must be 64 bytes"))?;
    let pk: [u8; 32] = pubkey.try_into()
        .map_err(|_| JsError::new("pubkey must be 32 bytes"))?;
    libveritas::verify_spaces_message(msg, &sig, &pk)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Verify a raw Schnorr signature (no prefix, caller provides the 32-byte message hash).
#[wasm_bindgen(js_name = "verifySchnorr")]
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

/// Decode stored zone bytes to a plain JS object.
#[wasm_bindgen(js_name = "decodeZone")]
pub fn decode_zone(bytes: &[u8]) -> Result<JsValue, JsError> {
    let zone = libveritas::Zone::from_slice(bytes)
        .map_err(|e| JsError::new(&format!("invalid zone: {e}")))?;
    zone_to_js(&zone)
}

/// Serialize a zone JS object to bytes for storage.
#[wasm_bindgen(js_name = "zoneToBytes")]
pub fn zone_to_bytes(zone: JsValue) -> Result<Vec<u8>, JsError> {
    let inner = zone_from_js(&zone)?;
    Ok(inner.to_bytes())
}

/// Compare two zones — returns true if `a` is fresher/better than `b`.
#[wasm_bindgen(js_name = "zoneIsBetterThan")]
pub fn zone_is_better_than(a: JsValue, b: JsValue) -> Result<bool, JsError> {
    let inner_a = zone_from_js(&a)?;
    let inner_b = zone_from_js(&b)?;
    inner_a.is_better_than(&inner_b)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Decode stored certificate bytes to a JS object.
#[wasm_bindgen(js_name = "decodeCertificate")]
pub fn decode_certificate(bytes: &[u8]) -> Result<JsValue, JsError> {
    let cert = libveritas::cert::Certificate::from_slice(bytes)
        .map_err(|e| JsError::new(&format!("invalid certificate: {e}")))?;
    to_js(&cert)
}
