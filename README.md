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
use libveritas::msg::{Message, QueryContext};

let anchors_json = std::fs::read("trust_anchors.json")?;
let veritas = Veritas::new()
    .with_anchors(serde_json::from_slice(&anchors_json)?)?;

let msg_bytes = std::fs::read("message.bin")?;
let msg = Message::from_slice(&msg_bytes)?;

let ctx = QueryContext::new();
let result = veritas.verify_message(&ctx, msg)?;

for zone in &result.zones {
    println!("{} -> {}", zone.handle, zone.sovereignty);
}
```

### JavaScript

```javascript
import { readFileSync } from "fs";
import { Veritas, QueryContext, Message } from "@spacesprotocol/libveritas";

const anchors = JSON.parse(readFileSync("trust_anchors.json", "utf8"));
const msg = new Message(readFileSync("message.bin"));

const veritas = new Veritas(anchors);
const ctx = new QueryContext();
const result = veritas.verifyMessage(ctx, msg);

for (const zone of result.zones()) {
  console.log(`${zone.handle()} -> ${zone.sovereignty()}`);
}
```

### Swift

```swift
import Libveritas

let anchorsJson = try String(contentsOfFile: "trust_anchors.json", encoding: .utf8)
let msgBytes = try Data(contentsOf: URL(fileURLWithPath: "message.bin"))

let anchors = try Anchors.fromJson(json: anchorsJson)
let veritas = try Veritas(anchors: anchors)

let msg = try Message(bytes: Array(msgBytes))
let ctx = QueryContext()
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
val msgBytes = File("message.bin").readBytes()

val anchors = Anchors.fromJson(anchorsJson)
val veritas = Veritas(anchors)

val msg = Message(msgBytes.toList())
val ctx = QueryContext()
val result = veritas.verifyMessage(ctx, msg)

for (zone in result.zones()) {
    println("${zone.handle()} -> ${zone.sovereignty()}")

    when (val c = zone.commitment()) {
        is CommitmentState.Exists ->
            println("  commitment at block ${c.blockHeight}")
        is CommitmentState.Empty ->
            println("  no commitment")
        is CommitmentState.Unknown ->
            println("  commitment unknown")
    }
}
```

### React Native

```typescript
import {
  Veritas,
  Anchors,
  QueryContext,
  Message,
} from '@spacesprotocol/react-native-libveritas';

const anchors = Anchors.fromJson(anchorsJsonString);
const veritas = new Veritas(anchors);

const ctx = new QueryContext();
const msg = new Message(messageBytes);
const result = veritas.verifyMessage(ctx, msg);

for (const zone of result.zones()) {
  console.log(`${zone.handle()} -> ${zone.sovereignty()}`);
}
```

### Python

```python
from libveritas import Anchors, Veritas, QueryContext, Message

anchors = Anchors.from_json(anchors_json_string)
veritas = Veritas(anchors)

msg = Message(message_bytes)
ctx = QueryContext()
result = veritas.verify_message(ctx, msg)

for zone in result.zones():
    print(f"{zone.handle()} -> {zone.sovereignty()}")
```

### Go

```go
import veritas "github.com/spacesprotocol/libveritas-go"

anchors, _ := veritas.AnchorsFromJson(anchorsJsonString)
v, _ := veritas.NewVeritas(anchors)

msg, _ := veritas.NewMessage(messageBytes)
ctx := veritas.NewQueryContext()
result, _ := v.VerifyMessage(ctx, msg)

for _, zone := range result.Zones() {
    fmt.Printf("%s -> %s\n", zone.Handle(), zone.Sovereignty())
}
```

## Query Context

By default, all handles in a message are verified. Use `QueryContext` to verify specific handles or provide previously-known zones for incremental verification:

```javascript
const ctx = new QueryContext();

// Only verify specific handles
ctx.addRequest("alice@bitcoin");

// Provide a previously stored zone for context
ctx.addZone(storedZoneBytes);

const result = veritas.verifyMessage(ctx, msg);
```

## Zone Comparison

When you have multiple zone snapshots for the same handle, use `is_better_than` to determine which is more recent:

```javascript
const better = newerZone.isBetterThan(olderZone); // true
```

Zones can be serialized for storage with `toBytes()` and later restored with `decodeZone()`.

## Guest ELF binaries

The compiled guest program ELF binaries are available behind the `elf` feature flag for provers:

```toml
[dependencies]
libveritas = { version = "0.1", features = ["elf"] }
```

```rust
use libveritas::constants::{FOLD_ELF, STEP_ELF, FOLD_ID, STEP_ID};
```

The image IDs (`FOLD_ID`, `STEP_ID`) are always available without the feature flag.

## Development

### Updating guest programs

When modifying the ZK guest programs in `methods/guest/src/bin/`, the baked ELF binaries and
image IDs must be updated. Run:

```bash
./update-elfs.sh
```

This will:
1. Build the guest programs reproducibly using Docker (`cargo risczero build`)
2. Copy the compiled ELF binaries to `veritas/elfs/`
3. Compute the image IDs and update `veritas/src/constants.rs`

Requirements: [RISC Zero toolchain](https://dev.risczero.com/api/zkvm/install) (`cargo-risczero`, `r0vm`) and Docker.
