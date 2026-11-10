/** A claim from `parseClaim` / `zoneClaims`. */
export interface Claim {
  /** The record key, e.g. "github". */
  key: string;
  values: string[];
  /** Canonical platform: "github", "x", "bluesky", "nostr", ... */
  platform: string;
  /** Canonical account. */
  account: string;
  profileUrl: string;
}

/** Overrides for the check context; anything left out keeps the default. */
export interface ClaimContext {
  /** x-only keys (64 hex chars) of the notaries to trust. Default: none. */
  trustedNotaries?: string[];
  /** Relays to ask for Nostr profiles, besides the claim's own hints. */
  nostrRelays?: string[];
  /** For servers checking many accounts. Never ship one in an app. */
  githubToken?: string;
}

export type ClaimOutcome =
  | {
      status: 'verified';
      platform: string;
      account: string;
      /** bio, display_name, website, post, bot_confirmation, well_known, handle_field */
      source: string;
      via: 'platform' | 'notary';
      accountId: string | null;
      notaryKey: string | null;
      issuedAt: number | null;
    }
  | {
      status: 'failed';
      reason:
        | 'no_proof'
        | 'not_found'
        | 'account_mismatch'
        | 'handle_not_found'
        | 'bad_response'
        | 'bad_notary_proof';
      message: string;
      found?: string;
    }
  | { status: 'unavailable'; message: string };

export interface VerifyClaimOptions {
  context?: ClaimContext;
  /** Defaults to `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
  /** Defaults to a WebSocket query of each relay. */
  queryRelays?: (relays: string[], filter: string, options: VerifyClaimOptions) => Promise<string[]>;
  /** Defaults to `globalThis.WebSocket`. */
  WebSocket?: typeof globalThis.WebSocket;
  /** Per request / per relay. Default 10000. */
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface VerifyClaimsOptions extends VerifyClaimOptions {
  /** Default 8. */
  maxConcurrent?: number;
  onResult?: (index: number, outcome: ClaimOutcome) => void;
}

/** Check one claim. `handle` is the verified zone's `handle`. */
export function verifyClaim(claim: Claim, handle: string, options?: VerifyClaimOptions): Promise<ClaimOutcome>;

/** Check several claims concurrently; outcomes are in `claims` order. */
export function verifyClaims(
  claims: Claim[],
  handle: string,
  options?: VerifyClaimsOptions,
): Promise<ClaimOutcome[]>;

export function queryRelays(relays: string[], filter: string, options?: VerifyClaimOptions): Promise<string[]>;