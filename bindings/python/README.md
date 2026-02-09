# libveritas

Python bindings for [libveritas](https://github.com/spacesprotocol/libveritas) — stateless verification for Bitcoin handles using the [Spaces protocol](https://spacesprotocol.org).

## Installation

```bash
pip install libveritas
```

## Usage

```python
from libveritas import VeritasAnchors, Veritas, VeritasQueryContext

# Load trust anchors
anchors = VeritasAnchors.from_json(anchors_json_string)
veritas = Veritas(anchors, dev_mode=False)

print(f"Anchors: {veritas.oldest_anchor()} .. {veritas.newest_anchor()}")

# Build query context (empty = verify all handles)
ctx = VeritasQueryContext()

# Verify a message
result = veritas.verify_message(ctx, message_bytes)

# Inspect verified zones
for zone in result.zones():
    print(f"{zone.handle()} -> {zone.sovereignty()}")

# Get certificates
for cert in result.certificates():
    print(f"{cert.subject} [{cert.cert_type}]")
```

## Building from source

Requires [Rust](https://rustup.rs/) and [maturin](https://www.maturin.rs/):

```bash
pip install maturin
cd python
maturin develop
```
