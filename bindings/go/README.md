# libveritas-go

Go bindings for [libveritas](https://github.com/spacesprotocol/libveritas) — stateless verification for Bitcoin handles using the [Spaces protocol](https://spacesprotocol.org).

## Installation

```bash
go get github.com/spacesprotocol/libveritas-go
```

## Usage

```go
package main

import (
    "fmt"
    veritas "github.com/spacesprotocol/libveritas-go"
)

func main() {
    // Load trust anchors
    anchors, err := veritas.VeritasAnchorsFromJson(anchorsJsonString)
    if err != nil {
        panic(err)
    }

    v, err := veritas.NewVeritas(anchors, false)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Anchors: %d .. %d\n", v.OldestAnchor(), v.NewestAnchor())

    // Build query context (empty = verify all handles)
    ctx := veritas.NewVeritasQueryContext()

    // Verify a message
    result, err := v.VerifyMessage(ctx, messageBytes)
    if err != nil {
        panic(err)
    }

    // Inspect verified zones
    for _, zone := range result.Zones() {
        fmt.Printf("%s -> %s\n", zone.Handle(), zone.Sovereignty())
    }
}
```

## Building from source

Requires [Rust](https://rustup.rs/) and [uniffi-bindgen-go](https://github.com/NordSecurity/uniffi-bindgen-go):

```bash
cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.4.0+v0.28.3

# Build the shared library
cargo build -p libveritas-uniffi --release

# Generate Go bindings
uniffi-bindgen-go --library target/release/liblibveritas_uniffi.dylib --out-dir go/
```
