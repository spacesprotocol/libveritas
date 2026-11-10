// Drives ClaimCheck with React Native's fetch and WebSocket.
//
//   const claims = zoneClaims(zone);
//   const outcomes = await verifyClaims(claims, zone.handle, {
//     onResult: (i, outcome) => render(claims[i], outcome),
//   });

import {
  ClaimCheck,
  ClaimContext,
  ClaimStep_Tags,
  type Claim,
  type ClaimOutcome,
  type ClaimStep,
} from './generated/libveritas_uniffi';

const MAX_BODY = 256 * 1024;

// Minimal shapes of the RN globals used here (the tsconfig has no DOM lib).
type FetchResponse = {
  status: number;
  url: string;
  arrayBuffer(): Promise<ArrayBuffer>;
};
type FetchFn = (
  url: string,
  init: { headers: Record<string, string>; signal?: unknown },
) => Promise<FetchResponse>;
type Signal = {
  aborted: boolean;
  reason?: unknown;
  addEventListener(type: 'abort', fn: () => void): void;
  removeEventListener(type: 'abort', fn: () => void): void;
};
type WebSocketLike = {
  readyState: number;
  send(data: string): void;
  close(): void;
  onopen: (() => void) | null;
  onmessage: ((msg: { data: unknown }) => void) | null;
  onerror: (() => void) | null;
  onclose: (() => void) | null;
};
type WebSocketCtor = new (url: string) => WebSocketLike;

export type VerifyClaimOptions = {
  /** Overrides for the check context; anything left out keeps the default. */
  context?: Partial<ClaimContext>;
  /** Defaults to the global `fetch`. */
  fetch?: FetchFn;
  /** Defaults to a WebSocket query of each relay. */
  queryRelays?: (relays: string[], filter: string, options: VerifyClaimOptions) => Promise<string[]>;
  /** Defaults to the global `WebSocket`. */
  WebSocket?: WebSocketCtor;
  /** Per request / per relay. Default 10000. */
  timeoutMs?: number;
  signal?: Signal;
};

export type VerifyClaimsOptions = VerifyClaimOptions & {
  /** Default 8. */
  maxConcurrent?: number;
  onResult?: (index: number, outcome: ClaimOutcome) => void;
};

const g = globalThis as unknown as {
  fetch: FetchFn;
  WebSocket: WebSocketCtor;
  AbortController: new () => { signal: Signal; abort(reason?: unknown): void };
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(t: unknown): void;
};

/**
 * Check one claim. `handle` is the verified zone's `handle`. Resolves to the
 * outcome; network errors come back as `Unavailable`, not as a rejection.
 */
export async function verifyClaim(
  claim: Claim,
  handle: string,
  options: VerifyClaimOptions = {},
): Promise<ClaimOutcome> {
  const context = options.context ? ClaimContext.create(options.context) : undefined;
  const check = new ClaimCheck(claim, handle, context);
  try {
    let step: ClaimStep = check.start();
    for (;;) {
      switch (step.tag) {
        case ClaimStep_Tags.Done:
          return step.inner.outcome;
        case ClaimStep_Tags.Fetch:
          step = await performFetch(check, step.inner, options);
          break;
        case ClaimStep_Tags.Query: {
          const query = options.queryRelays ?? queryRelays;
          const events = await query([...step.inner.relays], step.inner.filter, options);
          step = check.onEvents(events);
          break;
        }
      }
    }
  } finally {
    check.uniffiDestroy();
  }
}

/**
 * Check several claims for one handle concurrently. Resolves to outcomes in
 * the same order as `claims`; `onResult` fires as each one finishes.
 */
export async function verifyClaims(
  claims: Claim[],
  handle: string,
  options: VerifyClaimsOptions = {},
): Promise<ClaimOutcome[]> {
  const limit = Math.max(1, options.maxConcurrent ?? 8);
  const outcomes = new Array<ClaimOutcome>(claims.length);
  let next = 0;
  const worker = async () => {
    while (next < claims.length) {
      const i = next++;
      const outcome = await verifyClaim(claims[i]!, handle, options);
      outcomes[i] = outcome;
      options.onResult?.(i, outcome);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, claims.length) }, worker));
  return outcomes;
}

async function performFetch(
  check: ClaimCheck,
  req: { url: string; headers: ReadonlyArray<{ name: string; value: string }> },
  options: VerifyClaimOptions,
): Promise<ClaimStep> {
  const fetchFn = options.fetch ?? g.fetch;
  const headers: Record<string, string> = {};
  for (const h of req.headers) headers[h.name] = h.value;
  const timer = timeout(options);
  try {
    const resp = await fetchFn(req.url, { headers, signal: timer.signal });
    // RN's fetch has no streaming body; cap after reading.
    let body = await resp.arrayBuffer();
    if (body.byteLength > MAX_BODY + 1) body = body.slice(0, MAX_BODY + 1);
    return check.onResponse(resp.status, resp.url || req.url, body);
  } catch (e) {
    return check.onError(String((e as { message?: string })?.message ?? e));
  } finally {
    timer.clear();
  }
}

/**
 * Default relay query: sends `["REQ", sub, filter]` to each relay over
 * WebSocket and collects `EVENT` payloads until `EOSE`, `CLOSED` or the
 * timeout. A relay that fails just contributes no events.
 */
export async function queryRelays(
  relays: string[],
  filter: string,
  options: VerifyClaimOptions = {},
): Promise<string[]> {
  const results = await Promise.all(relays.map((r) => queryRelay(r, filter, options)));
  return results.flat();
}

function queryRelay(relay: string, filter: string, options: VerifyClaimOptions): Promise<string[]> {
  const WS = options.WebSocket ?? g.WebSocket;
  const sub = 'crossverify';
  return new Promise((resolve) => {
    const events: string[] = [];
    let ws: WebSocketLike | undefined;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      g.clearTimeout(timer);
      options.signal?.removeEventListener('abort', finish);
      try {
        if (ws?.readyState === 1) ws.send(JSON.stringify(['CLOSE', sub]));
        ws?.close();
      } catch {
        // already closed
      }
      resolve(events);
    };
    const timer = g.setTimeout(finish, options.timeoutMs ?? 10_000);
    options.signal?.addEventListener('abort', finish);
    try {
      ws = new WS(relay);
    } catch {
      finish();
      return;
    }
    ws.onopen = () => ws?.send(`["REQ","${sub}",${filter}]`);
    ws.onmessage = (msg) => {
      let v: unknown[];
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

function timeout(options: VerifyClaimOptions) {
  const ctrl = new g.AbortController();
  const timer = g.setTimeout(() => ctrl.abort(new Error('timed out')), options.timeoutMs ?? 10_000);
  const onAbort = () => ctrl.abort(options.signal?.reason);
  options.signal?.addEventListener('abort', onAbort);
  return {
    signal: ctrl.signal,
    clear: () => {
      g.clearTimeout(timer);
      options.signal?.removeEventListener('abort', onAbort);
    },
  };
}
