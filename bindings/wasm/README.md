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

## Building from source

Requires [Rust](https://rustup.rs/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/):

```bash
cargo install wasm-pack
wasm-pack build bindings/wasm --target web
```
