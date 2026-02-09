use std::str::FromStr;
use wasm_bindgen::prelude::*;

use libveritas::msg::Message;
use libveritas::sname::SName;
use libveritas::Zone;
use serde::Serialize;
use spaces_ptr::RootAnchor;

/// Serialize through JSON to get human-readable serde output
/// (hex hashes, string names, etc.) as a native JS object.
fn to_js<T: Serialize>(val: &T) -> Result<JsValue, JsError> {
    let json = serde_json::to_string(val).map_err(|e| JsError::new(&e.to_string()))?;
    js_sys::JSON::parse(&json).map_err(|_| JsError::new("json parse failed"))
}

#[wasm_bindgen]
pub struct QueryContext {
    inner: libveritas::msg::QueryContext,
}

#[wasm_bindgen]
impl QueryContext {
    #[wasm_bindgen(constructor)]
    pub fn new() -> QueryContext {
        QueryContext {
            inner: libveritas::msg::QueryContext::new(),
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
        let zone: Zone = borsh::from_slice(zone_bytes)
            .map_err(|e| JsError::new(&format!("invalid zone: {e}")))?;
        self.inner.add_zone(zone);
        Ok(())
    }
}

#[wasm_bindgen]
pub struct VeritasZone {
    inner: Zone,
}

#[wasm_bindgen]
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

    pub fn is_better_than(&self, other: &VeritasZone) -> Result<bool, JsError> {
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
        let inner =
            libveritas::Veritas::from_anchors(anchors).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Veritas { inner })
    }

    pub fn update(&mut self, anchors: JsValue) -> Result<(), JsError> {
        let anchors: Vec<RootAnchor> = serde_wasm_bindgen::from_value(anchors)
            .map_err(|e| JsError::new(&format!("invalid anchors: {e}")))?;
        self.inner
            .update(anchors)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn set_dev_mode(&mut self, enabled: bool) {
        self.inner.set_dev_mode(enabled);
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
        msg: &[u8],
    ) -> Result<VerifiedMessage, JsError> {
        let msg: Message =
            borsh::from_slice(msg).map_err(|e| JsError::new(&format!("invalid message: {e}")))?;

        let inner = self
            .inner
            .verify_message(&ctx.inner, msg)
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
    pub fn zones(&self) -> Vec<VeritasZone> {
        self.inner
            .zones
            .iter()
            .map(|z| VeritasZone { inner: z.clone() })
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

/// Decode stored zone bytes to a VeritasZone object.
#[wasm_bindgen]
pub fn decode_zone(bytes: &[u8]) -> Result<VeritasZone, JsError> {
    let zone: Zone =
        borsh::from_slice(bytes).map_err(|e| JsError::new(&format!("invalid zone: {e}")))?;
    Ok(VeritasZone { inner: zone })
}

/// Decode stored certificate bytes to a JS object.
#[wasm_bindgen]
pub fn decode_certificate(bytes: &[u8]) -> Result<JsValue, JsError> {
    let cert: libveritas::cert::Certificate =
        borsh::from_slice(bytes).map_err(|e| JsError::new(&format!("invalid certificate: {e}")))?;
    to_js(&cert)
}
