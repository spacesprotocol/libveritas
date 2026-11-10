# @spacesprotocol/libveritas

JavaScript/WASM bindings for [libveritas](https://github.com/spacesprotocol/libveritas) — stateless verification for Bitcoin handles using the [Spaces protocol](https://spacesprotocol.org).

## Installation

```bash
npm install @spacesprotocol/libveritas
```

## Usage

### Verifying a message

```javascript
import { Veritas, QueryContext, Message } from "@spacesprotocol/libveritas";

// Load trust anchors
const veritas = new Veritas(anchors);

console.log(`Anchors: ${veritas.oldestAnchor()} .. ${veritas.newestAnchor()}`);

// Build query context (empty = verify all handles)
const ctx = new QueryContext();
ctx.addRequest("alice@bitcoin");

// Verify a message (binary data from relay)
const msg = new Message(messageBytes);
const result = veritas.verifyMessage(ctx, msg);

// Inspect verified zones
for (const zone of result.zones()) {
  console.log(`${zone.handle()} -> ${zone.sovereignty()}`);

  // Store zone for later comparison
  const bytes = zone.toBytes();
}

// Compare zones
const better = newerZone.isBetterThan(olderZone);

// Get certificates
for (const cert of result.certificates()) {
  console.log(cert);
}
```

### Building a message

```javascript
import { MessageBuilder, RecordSet, OffchainData } from "@spacesprotocol/libveritas";

// Construct offchain data
let rs = new RecordSet(1, { nostr: "npub1...", ipv4: "127.0.0.1" });
let sig = wallet.signSchnorr(rs.id());
let offchainBytes = OffchainData.from(rs, sig);

// Build a message with certificates and offchain data
let builder = new MessageBuilder([
  { name: "@bitcoin", cert: rootCertBytes },
  { name: "alice@bitcoin", offchainData: offchainBytes, cert: leafCertBytes },
]);

// Get the chain proof request to send to a provider
let request = builder.chainProofRequest();

// ... send request to provider, get chain proof back ...

let msg = builder.build(chainProofBytes);

// Serialize for transport
let bytes = msg.toBytes();
```

### Updating offchain data

```javascript
// Update offchain data on a verified message (no cert changes)
let msg = result.message();

let rs = new RecordSet(2, { nostr: "npub1new..." });
let sig = wallet.signSchnorr(rs.id());
let offchainBytes = OffchainData.from(rs, sig);

msg.update([
  { name: "alice@bitcoin", offchainData: offchainBytes },
]);

let updatedBytes = msg.toBytes();
```

### Verifying account claims

A handle's records can claim accounts on other platforms
(`github: ["buffrr", "id:41967894"]`). `verifyClaims` checks that each account
points back at the handle, using `fetch` and `WebSocket`:

```javascript
import { zoneClaims, verifyClaims } from "@spacesprotocol/libveritas";

const zone = result.zones()[0];
const claims = zoneClaims(zone);   // [{ key, values, platform, account, profileUrl }]

const outcomes = await verifyClaims(claims, zone.handle, {
  onResult: (i, outcome) => render(claims[i], outcome), // as each finishes
});
// outcome.status: "verified" | "failed" | "unavailable"
```

Always pass the verified `zone.handle`, never the handle field of a SIG record.
Options: `context` (`trustedNotaries`, `nostrRelays`, ...), `fetch`,
`queryRelays`, `timeoutMs`, `signal`, `maxConcurrent`. For full control, drive
`ClaimCheck` yourself: `start()`, then `onResponse` / `onError` / `onEvents`
until a step has `type: "done"`.

In browsers, some platforms don't send CORS headers (X's oEmbed, most
websites' `/.well-known/spaces.txt`). For those, pass a `fetch` that goes
through your own proxy.

## Building from source

Requires [Rust](https://rustup.rs/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/):

```bash
cargo install wasm-pack
wasm-pack build bindings/wasm --target web
```
