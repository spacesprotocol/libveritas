# Libveritas

Stateless verification for Bitcoin handles using the [Spaces protocol](https://spacesprotocol.org).

Similar to [BIP-353](https://en.bitcoin.it/wiki/BIP_0353), but replaces centralized ICANN signing keys with a permissionless trust anchor.

## Installation

### Rust

```toml
[dependencies]
libveritas = { git = "https://github.com/spacesprotocol/libveritas.git" }
```

### JavaScript / Node.js

```bash
npm install @spacesprotocol/libveritas
```

### Swift (iOS / macOS)

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/spacesprotocol/libveritas-swift.git", from: "0.1.0")
]
```

### Kotlin / Android

```kotlin
// build.gradle.kts
dependencies {
    implementation("org.spacesprotocol:libveritas:0.1.0")
}
```

### React Native

```bash
npm install @spacesprotocol/react-native-libveritas
```

### Python

```bash
pip install libveritas
```

### Go

```bash
go get github.com/spacesprotocol/libveritas-go
```

## Usage

### Rust

```rust
use libveritas::Veritas;
use libveritas::msg::QueryContext;

let anchors_json = std::fs::read("trust_anchors.json")?;
let veritas = Veritas::from_anchors(serde_json::from_slice(&anchors_json)?)?;

let msg_bytes = std::fs::read("message.bin")?;
let msg = borsh::from_slice(&msg_bytes)?;

let ctx = QueryContext::new();
let result = veritas.verify_message(&ctx, msg)?;

for zone in &result.zones {
    println!("{} -> {}", zone.handle, zone.sovereignty);
}
```

### JavaScript

```javascript
import { readFileSync } from "fs";
import { Veritas, QueryContext } from "@spacesprotocol/libveritas";

const anchors = JSON.parse(readFileSync("trust_anchors.json", "utf8"));
const msg = readFileSync("message.bin");

const veritas = new Veritas(anchors);
const ctx = new QueryContext();
const result = veritas.verify_message(ctx, msg);

for (const zone of result.zones()) {
  console.log(`${zone.handle()} -> ${zone.sovereignty()}`);
}
```

### Swift

```swift
import Libveritas

let anchorsJson = try String(contentsOfFile: "trust_anchors.json", encoding: .utf8)
let msg = try Data(contentsOf: URL(fileURLWithPath: "message.bin"))

let anchors = try VeritasAnchors.fromJson(json: anchorsJson)
let veritas = try Veritas(anchors: anchors, devMode: false)

let ctx = VeritasQueryContext()
let result = try veritas.verifyMessage(ctx: ctx, msg: msg)

for zone in result.zones() {
    print("\(zone.handle()) -> \(zone.sovereignty())")

    switch zone.commitment() {
    case .exists(_, _, _, let blockHeight, _):
        print("  commitment at block \(blockHeight)")
    case .empty:
        print("  no commitment")
    case .unknown:
        print("  commitment unknown")
    }
}
```

### Kotlin

```kotlin
import uniffi.libveritas_uniffi.*

val anchorsJson = File("trust_anchors.json").readText()
val msg = File("message.bin").readBytes()

val anchors = VeritasAnchors.fromJson(anchorsJson)
val veritas = Veritas(anchors, devMode = false)

val ctx = VeritasQueryContext()
val result = veritas.verifyMessage(ctx, msg)

for (zone in result.zones()) {
    println("${zone.handle()} -> ${zone.sovereignty()}")

    when (val c = zone.commitment()) {
        is VeritasCommitmentState.Exists ->
            println("  commitment at block ${c.blockHeight}")
        is VeritasCommitmentState.Empty ->
            println("  no commitment")
        is VeritasCommitmentState.Unknown ->
            println("  commitment unknown")
    }
}
```

### React Native

```typescript
import {
  Veritas,
  VeritasAnchors,
  VeritasQueryContext,
} from '@spacesprotocol/react-native-libveritas';

const anchors = VeritasAnchors.fromJson(anchorsJsonString);
const veritas = new Veritas(anchors, false);

const ctx = new VeritasQueryContext();
const result = veritas.verifyMessage(ctx, messageBytes);

for (const zone of result.zones()) {
  console.log(`${zone.handle()} -> ${zone.sovereignty()}`);
}
```

### Python

```python
from libveritas import VeritasAnchors, Veritas, VeritasQueryContext

anchors = VeritasAnchors.from_json(anchors_json_string)
veritas = Veritas(anchors, dev_mode=False)

ctx = VeritasQueryContext()
result = veritas.verify_message(ctx, message_bytes)

for zone in result.zones():
    print(f"{zone.handle()} -> {zone.sovereignty()}")
```

### Go

```go
import veritas "github.com/spacesprotocol/libveritas-go"

anchors, _ := veritas.VeritasAnchorsFromJson(anchorsJsonString)
v, _ := veritas.NewVeritas(anchors, false)

ctx := veritas.NewVeritasQueryContext()
result, _ := v.VerifyMessage(ctx, messageBytes)

for _, zone := range result.Zones() {
    fmt.Printf("%s -> %s\n", zone.Handle(), zone.Sovereignty())
}
```

## Query Context

By default, all handles in a message are verified. Use `QueryContext` to verify specific handles or provide previously-known zones for incremental verification:

```javascript
const ctx = new QueryContext();

// Only verify specific handles
ctx.add_request("alice@bitcoin");

// Provide a previously stored zone for context
ctx.add_zone(storedZoneBytes);

const result = veritas.verify_message(ctx, msg);
```

## Zone Comparison

When you have multiple zone snapshots for the same handle, use `is_better_than` to determine which is more recent:

```javascript
const better = newerZone.is_better_than(olderZone); // true
```

Zones can be serialized for storage with `to_bytes()` and later restored with `decode_zone()`.
