//! ZK guest types and helpers for [`libveritas`](https://docs.rs/libveritas).
//!
//! Defines the [`guest::Commitment`] proven by the RISC Zero guest programs
//! and a [`BatchReader`] for reading the host-prepared input batches.

extern crate alloc;
extern crate core;

pub mod guest;

pub struct BatchReader<'a>(pub &'a [u8]);

pub struct Entry<'a> {
    pub handle: &'a [u8],
    pub value_hash: &'a [u8],
}

pub struct BodyIterator<'a> {
    data: &'a [u8],
}

impl<'a> BatchReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BatchReader(data)
    }

    pub fn iter(&self) -> BodyIterator<'a> {
        BodyIterator { data: self.0 }
    }
}

impl<'a> Iterator for BodyIterator<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < 64 {
            return None;
        }

        let subspace_hash = &self.data[..32];
        let value_hash = &self.data[32..64];
        self.data = &self.data[64..];

        Some(Entry {
            handle: subspace_hash,
            value_hash,
        })
    }
}
