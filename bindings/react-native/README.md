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

```typescript
import {
  Veritas,
  VeritasAnchors,
  VeritasQueryContext,
} from '@spacesprotocol/react-native-libveritas';

// Load trust anchors (e.g. fetched from a relay)
const anchors = VeritasAnchors.fromJson(anchorsJsonString);
const veritas = new Veritas(anchors, false);

console.log(`Anchors: ${veritas.oldestAnchor()} .. ${veritas.newestAnchor()}`);

// Build query context
const ctx = new VeritasQueryContext();
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
