//! Cross-platform account verification for Spaces handles.
//!
//! A handle's signed SIP-7 record set claims an account on another
//! platform (`{ "key": "github", "value": ["buffrr", "id:41967894"] }`);
//! this crate checks that the account points back at the handle. The client
//! passes in each claim as its record key and values ([`Claim`]); SIP-7
//! parsing stays in libveritas. See `design.md` in the repository root.
//!
//! The core does no I/O. A [`Check`] asks for one HTTP request or relay
//! query at a time and the caller performs it, so the same code runs
//! natively, in React Native (UniFFI) and in the browser (wasm). With the
//! `fetch` feature, [`fetch::Verifier`] performs them (reqwest, WebSockets),
//! checking many claims concurrently.
//!
//! - [`claim`]: reading a claim's values.
//! - [`check`]: the step machine, per platform.
//! - [`platform`]: platforms, record keys and account formats.
//! - [`matching`]: whether profile text, a link or a post points at a handle.
//! - [`notary`]: notary-signed proofs, for platforms a client can't check
//!   itself (Telegram, Instagram).
//! - [`nostr`]: npubs and event verification (NIP-SPACES).
//!
//! Dependencies match libveritas (bitcoin 0.32 / secp256k1 0.29, serde_json)
//! so the crate can live next to it in the same bindings.

pub mod check;
pub mod claim;
#[cfg(feature = "fetch")]
pub mod fetch;
mod handle;
mod html;
pub mod matching;
pub mod nostr;
pub mod notary;
pub mod platform;

pub use check::{
    Check, Context, Failure, Outcome, RelayQuery, Request, Response, Step, Verified, Via,
};
pub use claim::{Claim, ClaimError, Proof};
pub use handle::{Handle, HandleError};
pub use notary::Source;
pub use platform::Platform;
