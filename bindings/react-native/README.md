# @spacesprotocol/react-native-libveritas

React Native bindings for [libveritas](https://github.com/spacesprotocol/libveritas) — stateless verification for Bitcoin handles using the [Spaces protocol](https://spacesprotocol.org).

## Installation

```bash
npm install @spacesprotocol/react-native-libveritas
# or
yarn add @spacesprotocol/react-native-libveritas
```

For iOS, install pods:

```bash
cd ios && pod install
```

## Usage

### Verifying a message

```typescript
import {
  Veritas,
  Anchors,
  QueryContext,
} from '@spacesprotocol/react-native-libveritas';

// Load trust anchors
const anchors = Anchors.fromJson(anchorsJsonString);
const veritas = new Veritas(anchors);

console.log(`Anchors: ${veritas.oldestAnchor()} .. ${veritas.newestAnchor()}`);

// Build query context (empty = verify all handles)
const ctx = new QueryContext();
ctx.addRequest('alice@bitcoin');

// Verify a message (binary data from relay)
const result = veritas.verifyMessage(ctx, messageBytes);

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
  console.log(`${cert.subject} [${cert.certType}]`);
}
```

### Building a message

```typescript
import {
  MessageBuilder,
  RecordSet,
} from '@spacesprotocol/react-native-libveritas';
import { createOffchainData } from '@spacesprotocol/react-native-libveritas';

// Construct offchain data
const rs = new RecordSet(1, '{"nostr":"npub1...","ipv4":"127.0.0.1"}');
const sig = wallet.signSchnorr(rs.id());
const offchainBytes = createOffchainData(rs, sig);

// Build a message with certificates and offchain data
const builder = new MessageBuilder([
  { name: '@bitcoin', cert: rootCertBytes },
  { name: 'alice@bitcoin', offchainData: offchainBytes, cert: leafCertBytes },
]);

// Get the chain proof request to send to a provider
const request = builder.chainProofRequest();

// ... send request to provider, get chain proof back ...

const msg = builder.build(chainProofBytes);

// Serialize for transport
const bytes = msg.toBytes();
```

### Updating offchain data

```typescript
// Update offchain data on a verified message (no cert changes)
const msg = result.message();

const rs = new RecordSet(2, '{"nostr":"npub1new..."}');
const sig = wallet.signSchnorr(rs.id());
const offchainBytes = createOffchainData(rs, sig);

msg.update([
  { name: 'alice@bitcoin', offchainData: offchainBytes },
]);

const updatedBytes = msg.toBytes();
```

## Building from source

### Prerequisites

- [Rust](https://rustup.rs/) toolchain
- iOS targets: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`
- Android targets: `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android`
- [cargo-ndk](https://github.com/nickel-org/cargo-ndk) (for Android): `cargo install cargo-ndk`
- Android NDK (via Android Studio or `sdkmanager`)

### Build

```bash
cd react-native
yarn install
yarn ubrn:ios      # compile Rust for iOS + generate bindings
yarn ubrn:android  # compile Rust for Android + generate bindings
```
