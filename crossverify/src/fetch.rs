//! Performing checks (feature `fetch`): HTTP with reqwest, Nostr relays
//! over WebSocket. For the CLI and servers; apps drive [`Check`] with their
//! own `fetch` instead.
//!
//! ```ignore
//! let verifier = Verifier::new(Context::default());
//! let claims = [
//!     Claim::new("github", &["buffrr", "id:41967894"])?,
//!     Claim::new("x", &["_buffrr", "tweet:2100240557159112799"])?,
//! ];
//! // Results as they arrive, so a slow relay doesn't hold back the rest:
//! let mut results = verifier.verify_each("buffrr@bitcoin", &claims)?;
//! while let Some(Checked { index, outcome }) = results.next().await {
//!     println!("{}: {outcome}", claims[index].platform);
//! }
//! ```

use crate::check::MAX_BODY;
use crate::{Check, Claim, Context, HandleError, Outcome, RelayQuery, Request, Response, Step};
use futures::future::join_all;
use futures::stream::FuturesUnordered;
use futures::{SinkExt, Stream, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::Message;

/// One claim's result, from [`Verifier::verify_each`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// Position of the claim in the slice passed in.
    pub index: usize,
    pub outcome: Outcome,
}

/// Runs checks, many at once.
pub struct Verifier {
    http: reqwest::Client,
    ctx: Context,
    timeout: Duration,
    limit: Arc<Semaphore>,
}

impl Verifier {
    /// Defaults: 10 s per request or relay, at most 8 requests at a time.
    pub fn new(ctx: Context) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("crossverify/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("reqwest client");
        Verifier {
            http,
            ctx,
            timeout: Duration::from_secs(10),
            limit: Arc::new(Semaphore::new(8)),
        }
    }

    /// Time limit for each request, and for each relay to answer.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How many requests and relay connections may run at the same time.
    pub fn max_concurrent(mut self, n: usize) -> Self {
        self.limit = Arc::new(Semaphore::new(n.max(1)));
        self
    }

    pub fn context(&self) -> &Context {
        &self.ctx
    }

    /// Check one claim for `handle` (the verified zone's handle, see
    /// [`Check::new`]).
    pub async fn verify(&self, handle: &str, claim: &Claim) -> Result<Outcome, HandleError> {
        let mut check = Check::new(claim, handle, &self.ctx)?;
        let mut step = check.start();
        loop {
            step = match step {
                Step::Fetch(req) => {
                    let resp = self.get(&req).await;
                    check.on_response(resp)
                }
                Step::Query(q) => {
                    let events = self.query(&q).await;
                    check.on_events(events)
                }
                Step::Done(outcome) => return Ok(outcome),
            };
        }
    }

    /// Check all of a handle's claims concurrently, yielding each result as
    /// soon as it's ready (fastest first). Use this to show badges as they
    /// verify instead of waiting for the slowest platform.
    pub fn verify_each<'a>(
        &'a self,
        handle: &'a str,
        claims: &'a [Claim],
    ) -> Result<impl Stream<Item = Checked> + 'a, HandleError> {
        crate::Handle::parse(handle)?;
        Ok(claims
            .iter()
            .enumerate()
            .map(|(index, claim)| async move {
                let outcome = match self.verify(handle, claim).await {
                    Ok(o) => o,
                    // Unreachable: the handle was parsed above.
                    Err(e) => Outcome::Unavailable(e.to_string()),
                };
                Checked { index, outcome }
            })
            .collect::<FuturesUnordered<_>>())
    }

    /// Check all of a handle's claims concurrently and wait for all of
    /// them. Outcomes are in the same order as `claims`.
    pub async fn verify_all(
        &self,
        handle: &str,
        claims: &[Claim],
    ) -> Result<Vec<Outcome>, HandleError> {
        crate::Handle::parse(handle)?;
        let outcomes = join_all(claims.iter().map(|c| self.verify(handle, c))).await;
        outcomes.into_iter().collect()
    }

    async fn get(&self, req: &Request) -> Result<Response, String> {
        let _permit = self.limit.acquire().await.map_err(|e| e.to_string())?;
        let mut rb = self.http.get(&req.url).timeout(self.timeout);
        for h in &req.headers {
            rb = rb.header(&h.name, &h.value);
        }
        let mut resp = rb.send().await.map_err(|e| e.without_url().to_string())?;
        let status = resp.status().as_u16();
        let url = resp.url().to_string();
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| e.without_url().to_string())?
        {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BODY {
                break;
            }
        }
        Ok(Response { status, url, body })
    }

    async fn query(&self, q: &RelayQuery) -> Vec<String> {
        join_all(q.relays.iter().map(|r| self.query_relay(r, &q.filter)))
            .await
            .into_iter()
            .flatten()
            .collect()
    }

    /// Events from one relay; an empty list if it fails or times out.
    async fn query_relay(&self, relay: &str, filter: &str) -> Vec<String> {
        let Ok(_permit) = self.limit.acquire().await else {
            return vec![];
        };
        let sub = "crossverify";
        let run = async {
            let (mut ws, _) = tokio_tungstenite::connect_async(relay).await.ok()?;
            ws.send(Message::Text(format!(r#"["REQ","{sub}",{filter}]"#)))
                .await
                .ok()?;
            let mut events = Vec::new();
            while let Some(Ok(msg)) = ws.next().await {
                let Message::Text(text) = msg else { continue };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                    continue;
                };
                match v[0].as_str() {
                    Some("EVENT") if v[1] == sub => events.push(v[2].to_string()),
                    Some("EOSE" | "CLOSED") => break,
                    _ => {}
                }
            }
            let _ = ws
                .send(Message::Text(format!(r#"["CLOSE","{sub}"]"#)))
                .await;
            let _ = ws.close(None).await;
            Some(events)
        };
        tokio::time::timeout(self.timeout, run)
            .await
            .ok()
            .flatten()
            .unwrap_or_default()
    }
}
