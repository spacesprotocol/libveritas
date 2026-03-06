use std::str::FromStr;
use wasm_bindgen::prelude::*;

use libveritas::builder;
use libveritas::msg;
use libveritas::sname::SName;
use serde::Serialize;
use spaces_ptr::RootAnchor;

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

/// Parse a JS object into a DataUpdateRequest (name + offchain data, no cert).
fn parse_data_update(entry: &JsValue) -> Result<builder::DataUpdateRequest, JsError> {
    let name = js_sys::Reflect::get(entry, &"name".into())
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| JsError::new("name is required and must be a string"))?;

    let handle = SName::from_str(&name)
        .map_err(|e| JsError::new(&format!("invalid name '{}': {}", name, e)))?;

    let offchain_data = get_optional_bytes(entry, "offchainData")
        .map(|b| msg::OffchainData::from_slice(&b))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid offchain_data: {e}")))?;

    let delegate_offchain_data = get_optional_bytes(entry, "delegateOffchainData")
        .map(|b| msg::OffchainData::from_slice(&b))
        .transpose()
        .map_err(|e| JsError::new(&format!("invalid delegate_offchain_data: {e}")))?;

    Ok(builder::DataUpdateRequest {
        handle,
        offchain_data,
        delegate_offchain_data,
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

    /// Update offchain data on this message.
    ///
    /// Accepts a JS array of data update entries:
    /// ```js
    /// msg.update([
    ///   { name: "alice@bitcoin", offchainData: Uint8Array },
    ///   { name: "@bitcoin", delegateOffchainData: Uint8Array }
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
    ///   { name: "@bitcoin", offchainData: Uint8Array, cert: Uint8Array },
    ///   { name: "alice@bitcoin", offchainData: Uint8Array, cert: Uint8Array }
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

/// Serialized records ready to be signed.
///
/// ```js
/// let rs = new RecordSet(1, { nostr: "npub1...", ipv4: "127.0.0.1" });
/// let sig = wallet.signSchnorr(rs.id());
/// let offchainBytes = OffchainData.from(rs, sig);
/// ```
#[wasm_bindgen]
pub struct RecordSet {
    inner: Option<msg::RecordSet>,
}

#[wasm_bindgen]
impl RecordSet {
    /// Create a record set from a sequence number and a JS object of key-value pairs.
    #[wasm_bindgen(constructor)]
    pub fn new(seq: u32, records: JsValue) -> Result<RecordSet, JsError> {
        let entries = js_sys::Object::entries(&records.into());
        let mut recs = Vec::with_capacity(entries.length() as usize);
        for i in 0..entries.length() {
            let pair = js_sys::Array::from(&entries.get(i));
            let key = pair.get(0).as_string()
                .ok_or_else(|| JsError::new("record key must be a string"))?;
            let value = pair.get(1).as_string()
                .ok_or_else(|| JsError::new("record value must be a string"))?;
            recs.push(libveritas::records::Record { name: key, value });
        }
        Ok(RecordSet {
            inner: Some(msg::RecordSet::new(seq, &recs)),
        })
    }

    /// The 32-byte hash to sign.
    pub fn id(&self) -> Result<Vec<u8>, JsError> {
        let rs = self.inner.as_ref()
            .ok_or_else(|| JsError::new("record set already consumed"))?;
        Ok(rs.id().to_vec())
    }
}

/// Helpers for constructing OffchainData.
#[wasm_bindgen]
pub struct OffchainData;

#[wasm_bindgen]
impl OffchainData {
    /// Create borsh-encoded OffchainData from a RecordSet and a 64-byte Schnorr signature.
    ///
    /// Consumes the RecordSet.
    #[wasm_bindgen(js_name = "from")]
    pub fn from_record_set(record_set: &mut RecordSet, signature: &[u8]) -> Result<Vec<u8>, JsError> {
        let rs = record_set.inner.take()
            .ok_or_else(|| JsError::new("record set already consumed"))?;
        let sig: [u8; 64] = signature.try_into()
            .map_err(|_| JsError::new("signature must be 64 bytes"))?;
        let offchain = msg::OffchainData::from_record_set(
            rs,
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
