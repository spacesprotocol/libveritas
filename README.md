# Libveritas

Stateless verification for Bitcoin handles using the [Spaces protocol](https://spacesprotocol.org).

Similar to [BIP-353](https://en.bitcoin.it/wiki/BIP_0353), but replaces centralized ICANN signing keys with a permissionless trust anchor.

## Usage

Verifying the handle `alice@bitcoin`:

```rust
use std::fs;
use libveritas::Veritas;

let anchors = fs::read("trust_anchors.json")?; // created by spaced
let veritas = Veritas::from_anchors(serde_json::from_slice(&anchors)?)?;

let bitcoin_cert = fs::read("bitcoin.cert")?;
let alice_cert = fs::read("alice_bitcoin.cert")?;

// verify @bitcoin top level handle
let bitcoin_zone = veritas.verify(bitcoin_cert, None)?;

// verify an off-chain handle e.g. alice@bitcoin
let alice_zone = veritas.verify(alice_cert, Some(&bitcoin_zone))?;

println!("@bitcoin zone: {:?}", bitcoin_zone);
println!("alice@bitcoin zone: {:?}", alice_zone);
```

That's it!

