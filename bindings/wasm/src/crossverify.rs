//! Cross-platform account verification (libveritas_crossverify).
//!
//! The step machine is exposed as is: `ClaimCheck` asks for one HTTP request
//! or relay query at a time and the caller performs it. `claims.js` wraps it
//! in `verifyClaim` / `verifyClaims`, which use the platform's `fetch` and
//! `WebSocket`.

use libveritas_crossverify as cv;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

use crate::{to_js, zone_from_js};

/// A claim as a plain JS object. `key` and `values` are what the check is
/// built from; the rest is for display.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimJs {
    key: String,
    values: Vec<String>,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    account: String,
    #[serde(default)]
    profile_url: String,
}

impl ClaimJs {
    fn new(key: &str, values: Vec<String>, claim: &cv::Claim) -> ClaimJs {
        ClaimJs {
            key: key.to_string(),
            values,
            platform: claim.platform.as_str().to_string(),
            account: claim.account.clone(),
            profile_url: claim.profile_url(),
        }
    }
}

/// Optional overrides for `cv::Context`; anything left out keeps the
/// default.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ContextJs {
    /// x-only notary keys, hex.
    trusted_notaries: Option<Vec<String>>,
    nostr_relays: Option<Vec<String>>,
    github_token: Option<String>,
}

impl ContextJs {
    fn into_context(self) -> Result<cv::Context, JsError> {
        let mut ctx = cv::Context::default();
        if let Some(keys) = self.trusted_notaries {
            ctx.trusted_notaries = keys
                .iter()
                .map(|k| parse_key(k))
                .collect::<Result<_, _>>()?;
        }
        if let Some(r) = self.nostr_relays {
            ctx.nostr_relays = r;
        }
        ctx.github_token = self.github_token;
        Ok(ctx)
    }
}

fn parse_key(hex: &str) -> Result<[u8; 32], JsError> {
    let err = || {
        JsError::new(&format!(
            "invalid notary key {hex:?}: expected 64 hex chars"
        ))
    };
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(err());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| err())?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_js<T: for<'de> Deserialize<'de>>(val: &JsValue, what: &str) -> Result<T, JsError> {
    let json = js_sys::JSON::stringify(val)
        .ok()
        .and_then(|s| s.as_string())
        .ok_or_else(|| JsError::new(&format!("invalid {what}")))?;
    serde_json::from_str(&json).map_err(|e| JsError::new(&format!("invalid {what}: {e}")))
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum StepJs {
    /// HTTP GET `url` with `headers`.
    Fetch {
        url: String,
        headers: BTreeMap<String, String>,
    },
    /// Send `["REQ", <id>, filter]` to each relay and collect the events.
    Query {
        relays: Vec<String>,
        filter: String,
    },
    Done {
        outcome: OutcomeJs,
    },
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum OutcomeJs {
    #[serde(rename_all = "camelCase")]
    Verified {
        platform: String,
        account: String,
        /// Where the link was found: bio, display_name, website, post, ...
        source: String,
        /// "platform" (checked directly) or "notary".
        via: &'static str,
        account_id: Option<String>,
        /// Hex x-only key of the notary, when `via` is "notary".
        notary_key: Option<String>,
        /// Unix seconds when the notary checked, when `via` is "notary".
        issued_at: Option<u64>,
    },
    Failed {
        /// no_proof, not_found, account_mismatch, handle_not_found,
        /// bad_response or bad_notary_proof.
        reason: &'static str,
        message: String,
        /// The account the proof actually belongs to (account_mismatch).
        #[serde(skip_serializing_if = "Option::is_none")]
        found: Option<String>,
    },
    /// Couldn't tell (network error, rate limit, platform down). Try later.
    Unavailable { message: String },
}

impl From<cv::Outcome> for OutcomeJs {
    fn from(o: cv::Outcome) -> Self {
        match o {
            cv::Outcome::Verified(v) => {
                let (via, notary_key, issued_at) = match v.via {
                    cv::Via::Platform => ("platform", None, None),
                    cv::Via::Notary { key, issued_at } => {
                        ("notary", Some(hex(&key)), Some(issued_at))
                    }
                };
                OutcomeJs::Verified {
                    platform: v.platform.as_str().to_string(),
                    account: v.account,
                    source: v.source.as_str().to_string(),
                    via,
                    account_id: v.account_id,
                    notary_key,
                    issued_at,
                }
            }
            cv::Outcome::Failed(f) => {
                let message = f.to_string();
                let (reason, found) = match f {
                    cv::Failure::NoProof => ("no_proof", None),
                    cv::Failure::NotFound => ("not_found", None),
                    cv::Failure::AccountMismatch { found } => ("account_mismatch", Some(found)),
                    cv::Failure::HandleNotFound => ("handle_not_found", None),
                    cv::Failure::BadResponse(_) => ("bad_response", None),
                    cv::Failure::BadNotaryProof(_) => ("bad_notary_proof", None),
                };
                OutcomeJs::Failed {
                    reason,
                    message,
                    found,
                }
            }
            cv::Outcome::Unavailable(message) => OutcomeJs::Unavailable { message },
        }
    }
}

fn step_to_js(step: cv::Step) -> Result<JsValue, JsError> {
    let s = match step {
        cv::Step::Fetch(r) => StepJs::Fetch {
            url: r.url,
            headers: r.headers.into_iter().map(|h| (h.name, h.value)).collect(),
        },
        cv::Step::Query(q) => StepJs::Query {
            relays: q.relays,
            filter: q.filter,
        },
        cv::Step::Done(o) => StepJs::Done { outcome: o.into() },
    };
    to_js(&s)
}

/// Read a claim from a record key and its values, e.g.
/// `parseClaim("github", ["buffrr", "id:41967894"])`.
///
/// Returns `{ key, values, platform, account, profileUrl }`. Throws for keys
/// that aren't a supported platform or an invalid account.
#[wasm_bindgen(js_name = "parseClaim")]
pub fn parse_claim(key: &str, values: Vec<String>) -> Result<JsValue, JsError> {
    let claim = cv::Claim::new(key, &values).map_err(|e| JsError::new(&e.to_string()))?;
    to_js(&ClaimJs::new(key, values, &claim))
}

/// The account claims in a verified zone's records, in record order.
///
/// Reads the owner's off-chain records, or the on-chain fallback records
/// when there are none. Records that aren't a supported platform, or whose
/// account is invalid, are skipped.
#[wasm_bindgen(js_name = "zoneClaims")]
pub fn zone_claims(zone: JsValue) -> Result<JsValue, JsError> {
    let zone = zone_from_js(&zone)?;
    let records = if zone.records.is_empty() {
        &zone.fallback_records
    } else {
        &zone.records
    };
    let parsed = records
        .unpack()
        .map_err(|e| JsError::new(&format!("invalid records: {e}")))?;
    let claims: Vec<ClaimJs> = parsed
        .iter()
        .filter_map(|r| match r {
            sip7::ParsedRecord::Txt { key, value } => {
                let values: Vec<String> = value.iter().map(String::from).collect();
                let claim = cv::Claim::new(key, &values).ok()?;
                Some(ClaimJs::new(key, values, &claim))
            }
            _ => None,
        })
        .collect();
    to_js(&claims)
}

/// Checks one claim. Drive it with `start()`, then hand each request's
/// result back with `onResponse` / `onError` / `onEvents` until a step has
/// `type: "done"`. `verifyClaim` in `claims.js` does this for you.
#[wasm_bindgen]
pub struct ClaimCheck {
    inner: cv::Check,
}

#[wasm_bindgen]
impl ClaimCheck {
    /// `claim` is from `parseClaim` / `zoneClaims` (only `key` and `values`
    /// are read). `handle` is the verified zone's handle (`zone.handle`),
    /// never the SIG record's handle field, which libveritas doesn't check.
    /// `context` optionally overrides `{ trustedNotaries: hex[],
    /// nostrRelays, githubToken }`.
    #[wasm_bindgen(constructor)]
    pub fn new(claim: JsValue, handle: &str, context: JsValue) -> Result<ClaimCheck, JsError> {
        let c: ClaimJs = from_js(&claim, "claim")?;
        let claim = cv::Claim::new(&c.key, &c.values).map_err(|e| JsError::new(&e.to_string()))?;
        let ctx = if context.is_undefined() || context.is_null() {
            ContextJs::default()
        } else {
            from_js(&context, "context")?
        }
        .into_context()?;
        let inner = cv::Check::new(&claim, handle, &ctx)
            .map_err(|e| JsError::new(&format!("invalid handle {handle:?}: {e}")))?;
        Ok(ClaimCheck { inner })
    }

    /// The first step.
    pub fn start(&mut self) -> Result<JsValue, JsError> {
        step_to_js(self.inner.start())
    }

    /// The response to the last `fetch` step. `url` is the final URL after
    /// redirects.
    #[wasm_bindgen(js_name = "onResponse")]
    pub fn on_response(
        &mut self,
        status: u16,
        url: String,
        body: Vec<u8>,
    ) -> Result<JsValue, JsError> {
        step_to_js(
            self.inner
                .on_response(Ok(cv::Response { status, url, body })),
        )
    }

    /// The last `fetch` step's request failed (network error, timeout,
    /// CORS).
    #[wasm_bindgen(js_name = "onError")]
    pub fn on_error(&mut self, message: String) -> Result<JsValue, JsError> {
        step_to_js(self.inner.on_response(Err(message)))
    }

    /// The raw `EVENT` payloads (JSON strings) from the last `query` step,
    /// from all relays together.
    #[wasm_bindgen(js_name = "onEvents")]
    pub fn on_events(&mut self, events: Vec<String>) -> Result<JsValue, JsError> {
        step_to_js(self.inner.on_events(events))
    }
}
