//! Cross-platform account verification (libveritas_crossverify).
//!
//! The step machine is exposed as is: `ClaimCheck` asks for one HTTP request
//! or relay query at a time and the caller performs it with the platform's
//! own networking. The React Native package wraps it in `verifyClaim` /
//! `verifyClaims`.

use std::sync::Mutex;

use libveritas_crossverify as cv;

use crate::{VeritasError, Zone};

fn invalid(msg: impl ToString) -> VeritasError {
    VeritasError::InvalidInput {
        msg: msg.to_string(),
    }
}

/// An account claim: a record key and its values. `key` and `values` are
/// what a check is built from; the rest is for display.
#[derive(uniffi::Record, Clone)]
pub struct Claim {
    /// The record key, e.g. "github".
    pub key: String,
    pub values: Vec<String>,
    /// Canonical platform: "github", "x", "bluesky", "nostr", ...
    pub platform: String,
    /// Canonical account.
    pub account: String,
    pub profile_url: String,
}

impl Claim {
    fn new(key: &str, values: Vec<String>, claim: &cv::Claim) -> Claim {
        Claim {
            key: key.to_string(),
            values,
            platform: claim.platform.as_str().to_string(),
            account: claim.account.clone(),
            profile_url: claim.profile_url(),
        }
    }
}

/// Overrides for the check context. Fields left as `None` keep the default.
#[derive(uniffi::Record, Default)]
pub struct ClaimContext {
    /// x-only keys (32 bytes) of the notaries to trust.
    #[uniffi(default = [])]
    pub trusted_notaries: Vec<Vec<u8>>,
    /// Relays to ask for Nostr profiles, besides the claim's own hints.
    #[uniffi(default = None)]
    pub nostr_relays: Option<Vec<String>>,
    /// For servers checking many accounts. Never ship one in an app.
    #[uniffi(default = None)]
    pub github_token: Option<String>,
}

impl ClaimContext {
    fn to_context(&self) -> Result<cv::Context, VeritasError> {
        let defaults = cv::Context::default();
        let trusted_notaries = self
            .trusted_notaries
            .iter()
            .map(|k| {
                <[u8; 32]>::try_from(k.as_slice())
                    .map_err(|_| invalid(format!("notary key must be 32 bytes, got {}", k.len())))
            })
            .collect::<Result<_, _>>()?;
        Ok(cv::Context {
            trusted_notaries,
            nostr_relays: self.nostr_relays.clone().unwrap_or(defaults.nostr_relays),
            github_token: self.github_token.clone(),
        })
    }
}

#[derive(uniffi::Record)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(uniffi::Enum)]
pub enum ClaimStep {
    /// HTTP GET `url` with `headers`, then call `on_response` (or
    /// `on_error`).
    Fetch {
        url: String,
        headers: Vec<HttpHeader>,
    },
    /// Send `["REQ", <id>, filter]` to each relay over WebSocket, collect the
    /// `EVENT` payloads until `EOSE` or a timeout, then call `on_events`.
    Query {
        relays: Vec<String>,
        filter: String,
    },
    Done {
        outcome: ClaimOutcome,
    },
}

#[derive(uniffi::Enum)]
pub enum ClaimVia {
    /// Checked against the platform directly.
    Platform,
    /// A trusted notary's signed attestation.
    Notary { key: Vec<u8>, issued_at: u64 },
}

#[derive(uniffi::Enum)]
pub enum ClaimFailure {
    /// The claim has no proof that can be checked.
    NoProof,
    /// The account, post or file doesn't exist (or is private).
    NotFound,
    /// The proof belongs to a different account (see `found`).
    AccountMismatch,
    /// The account exists but doesn't point back at the handle.
    HandleNotFound,
    BadResponse,
    BadNotaryProof,
}

#[derive(uniffi::Enum)]
pub enum ClaimOutcome {
    Verified {
        platform: String,
        account: String,
        /// Where the link was found: bio, display_name, website, post,
        /// bot_confirmation, well_known, handle_field.
        source: String,
        via: ClaimVia,
        /// Stable platform ID when known (GitHub, Bluesky DID, ...).
        account_id: Option<String>,
    },
    Failed {
        reason: ClaimFailure,
        message: String,
        /// The account the proof actually belongs to (`AccountMismatch`).
        found: Option<String>,
    },
    /// Couldn't tell (network error, rate limit, platform down). Try later.
    Unavailable { message: String },
}

impl From<cv::Outcome> for ClaimOutcome {
    fn from(o: cv::Outcome) -> Self {
        match o {
            cv::Outcome::Verified(v) => ClaimOutcome::Verified {
                platform: v.platform.as_str().to_string(),
                account: v.account,
                source: v.source.as_str().to_string(),
                via: match v.via {
                    cv::Via::Platform => ClaimVia::Platform,
                    cv::Via::Notary { key, issued_at } => ClaimVia::Notary {
                        key: key.to_vec(),
                        issued_at,
                    },
                },
                account_id: v.account_id,
            },
            cv::Outcome::Failed(f) => {
                let message = f.to_string();
                let (reason, found) = match f {
                    cv::Failure::NoProof => (ClaimFailure::NoProof, None),
                    cv::Failure::NotFound => (ClaimFailure::NotFound, None),
                    cv::Failure::AccountMismatch { found } => {
                        (ClaimFailure::AccountMismatch, Some(found))
                    }
                    cv::Failure::HandleNotFound => (ClaimFailure::HandleNotFound, None),
                    cv::Failure::BadResponse(_) => (ClaimFailure::BadResponse, None),
                    cv::Failure::BadNotaryProof(_) => (ClaimFailure::BadNotaryProof, None),
                };
                ClaimOutcome::Failed {
                    reason,
                    message,
                    found,
                }
            }
            cv::Outcome::Unavailable(message) => ClaimOutcome::Unavailable { message },
        }
    }
}

impl From<cv::Step> for ClaimStep {
    fn from(step: cv::Step) -> Self {
        match step {
            cv::Step::Fetch(r) => ClaimStep::Fetch {
                url: r.url,
                headers: r
                    .headers
                    .into_iter()
                    .map(|h| HttpHeader {
                        name: h.name,
                        value: h.value,
                    })
                    .collect(),
            },
            cv::Step::Query(q) => ClaimStep::Query {
                relays: q.relays,
                filter: q.filter,
            },
            cv::Step::Done(o) => ClaimStep::Done { outcome: o.into() },
        }
    }
}

/// Read a claim from a record key and its values, e.g.
/// `parse_claim("github", ["buffrr", "id:41967894"])`.
#[uniffi::export]
pub fn parse_claim(key: String, values: Vec<String>) -> Result<Claim, VeritasError> {
    let claim = cv::Claim::new(&key, &values).map_err(invalid)?;
    Ok(Claim::new(&key, values, &claim))
}

/// The account claims in a verified zone's records, in record order.
///
/// Reads the owner's off-chain records, or the on-chain fallback records
/// when there are none. Records that aren't a supported platform, or whose
/// account is invalid, are skipped.
#[uniffi::export]
pub fn zone_claims(zone: Zone) -> Result<Vec<Claim>, VeritasError> {
    let bytes = if zone.records.is_empty() {
        zone.fallback_records
    } else {
        zone.records
    };
    let records = sip7::RecordSet::new(bytes);
    let parsed = records
        .unpack()
        .map_err(|e| invalid(format!("invalid records: {e}")))?;
    Ok(parsed
        .iter()
        .filter_map(|r| match r {
            sip7::ParsedRecord::Txt { key, value } => {
                let values: Vec<String> = value.iter().map(String::from).collect();
                let claim = cv::Claim::new(key, &values).ok()?;
                Some(Claim::new(key, values, &claim))
            }
            _ => None,
        })
        .collect())
}

/// Checks one claim. Call `start()`, perform each step and hand the result
/// back, until a step is `Done`.
#[derive(uniffi::Object)]
pub struct ClaimCheck {
    inner: Mutex<cv::Check>,
}

#[uniffi::export]
impl ClaimCheck {
    /// `handle` is the verified zone's `handle`, never the SIG record's
    /// handle field, which libveritas doesn't check.
    #[uniffi::constructor]
    pub fn new(
        claim: Claim,
        handle: String,
        context: Option<ClaimContext>,
    ) -> Result<Self, VeritasError> {
        let parsed = cv::Claim::new(&claim.key, &claim.values).map_err(invalid)?;
        let ctx = context.unwrap_or_default().to_context()?;
        let check = cv::Check::new(&parsed, &handle, &ctx)
            .map_err(|e| invalid(format!("invalid handle {handle:?}: {e}")))?;
        Ok(ClaimCheck {
            inner: Mutex::new(check),
        })
    }

    pub fn start(&self) -> ClaimStep {
        self.inner.lock().unwrap().start().into()
    }

    /// The response to the last `Fetch` step. `url` is the final URL after
    /// redirects.
    pub fn on_response(&self, status: u16, url: String, body: Vec<u8>) -> ClaimStep {
        self.inner
            .lock()
            .unwrap()
            .on_response(Ok(cv::Response { status, url, body }))
            .into()
    }

    /// The last `Fetch` step's request failed (network error, timeout).
    pub fn on_error(&self, message: String) -> ClaimStep {
        self.inner.lock().unwrap().on_response(Err(message)).into()
    }

    /// The raw `EVENT` payloads (JSON strings) from the last `Query` step,
    /// from all relays together.
    pub fn on_events(&self, events: Vec<String>) -> ClaimStep {
        self.inner.lock().unwrap().on_events(events).into()
    }
}
