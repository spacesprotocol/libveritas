# libveritas

Python bindings for [libveritas](https://github.com/spacesprotocol/libveritas) — stateless verification for Bitcoin handles using the [Spaces protocol](https://spacesprotocol.org).

## Installation

```bash
pip install libveritas
```

## Usage

```python
from libveritas import Anchors, Veritas, QueryContext, Message

# Load trust anchors
anchors = Anchors.from_json(anchors_json_string)
veritas = Veritas(anchors)

print(f"Anchors: {veritas.oldest_anchor()} .. {veritas.newest_anchor()}")

# Build query context (empty = verify all handles)
ctx = QueryContext()

# Verify a message
msg = Message(message_bytes)
result = veritas.verify_message(ctx, msg)

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
