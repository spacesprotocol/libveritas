// Drives ClaimCheck with the platform's fetch and WebSocket.
//
//   const zone = verified.zones()[0];
//   const claims = zoneClaims(zone);
//   const outcomes = await verifyClaims(claims, zone.handle, {
//     onResult: (i, outcome) => render(claims[i], outcome),
//   });
//
// In browsers some platforms don't send CORS headers (X's oEmbed, most
// websites' /.well-known/spaces.txt). Pass a `fetch` that goes through your
// own proxy for those, or run the check server side.

import { ClaimCheck } from './libveritas.js';

const MAX_BODY = 256 * 1024;

/**
 * Check one claim. Resolves to its outcome; never rejects for network
 * errors (those come back as `{ status: "unavailable" }`).
 */
export async function verifyClaim(claim, handle, options = {}) {
  const check = new ClaimCheck(claim, handle, options.context);
  try {
    let step = check.start();
    for (;;) {
      if (step.type === 'done') return step.outcome;
      if (step.type === 'fetch') {
        step = await performFetch(check, step, options);
      } else {
        const query = options.queryRelays ?? queryRelays;
        const events = await query(step.relays, step.filter, options);
        step = check.onEvents(events);
      }
    }
  } finally {
    check.free?.();
  }
}

/**
 * Check several claims for one handle concurrently. Resolves to outcomes in
 * the same order as `claims`; `options.onResult(index, outcome)` fires as
 * each one finishes, so badges can update without waiting for the slowest.
 */
export async function verifyClaims(claims, handle, options = {}) {
  const limit = Math.max(1, options.maxConcurrent ?? 8);
  const outcomes = new Array(claims.length);
  let next = 0;
  const worker = async () => {
    while (next < claims.length) {
      const i = next++;
      outcomes[i] = await verifyClaim(claims[i], handle, options);
      options.onResult?.(i, outcomes[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, claims.length) }, worker));
  return outcomes;
}

async function performFetch(check, step, options) {
  const fetchFn = options.fetch ?? globalThis.fetch;
  const timer = timeout(options);
  try {
    const resp = await fetchFn(step.url, {
      headers: step.headers,
      redirect: 'follow',
      signal: timer.signal,
    });
    const body = await readBody(resp);
    return check.onResponse(resp.status, resp.url || step.url, body);
  } catch (e) {
    return check.onError(String(e?.message ?? e));
  } finally {
    timer.clear();
  }
}

/** Reads at most MAX_BODY + 1 bytes; the check rejects anything larger. */
async function readBody(resp) {
  const reader = resp.body?.getReader?.();
  if (!reader) return new Uint8Array(await resp.arrayBuffer());
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
    if (size > MAX_BODY) {
      reader.cancel().catch(() => {});
      break;
    }
  }
  const body = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    body.set(c, at);
    at += c.length;
  }
  return body;
}

/**
 * Default relay query: sends `["REQ", sub, filter]` to each relay over
 * WebSocket and collects `EVENT` payloads until `EOSE`, `CLOSED` or the
 * timeout. A relay that fails just contributes no events.
 */
export async function queryRelays(relays, filter, options = {}) {
  const results = await Promise.all(relays.map((r) => queryRelay(r, filter, options)));
  return results.flat();
}

function queryRelay(relay, filter, options) {
  const WS = options.WebSocket ?? globalThis.WebSocket;
  const ms = options.timeoutMs ?? 10_000;
  const sub = 'crossverify';
  return new Promise((resolve) => {
    const events = [];
    let ws;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      options.signal?.removeEventListener?.('abort', finish);
      try {
        if (ws?.readyState === 1) ws.send(JSON.stringify(['CLOSE', sub]));
        ws?.close();
      } catch {}
      resolve(events);
    };
    const timer = setTimeout(finish, ms);
    options.signal?.addEventListener?.('abort', finish);
    try {
      ws = new WS(relay);
    } catch {
      finish();
      return;
    }
    ws.onopen = () => ws.send(`["REQ","${sub}",${filter}]`);
    ws.onmessage = (msg) => {
      let v;
      try {
        v = JSON.parse(typeof msg.data === 'string' ? msg.data : String(msg.data));
      } catch {
        return;
      }
      if (v[0] === 'EVENT' && v[1] === sub) events.push(JSON.stringify(v[2]));
      else if (v[0] === 'EOSE' || v[0] === 'CLOSED') finish();
    };
    ws.onerror = finish;
    ws.onclose = finish;
  });
}

function timeout(options) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error('timed out')), options.timeoutMs ?? 10_000);
  const onAbort = () => ctrl.abort(options.signal.reason);
  options.signal?.addEventListener?.('abort', onAbort);
  return {
    signal: ctrl.signal,
    clear: () => {
      clearTimeout(timer);
      options.signal?.removeEventListener?.('abort', onAbort);
    },
  };
}