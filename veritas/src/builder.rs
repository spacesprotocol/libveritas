use std::collections::HashMap;
use crate::cert::{Certificate, CertificateChain, ChainProofRequestUtils, Witness};
use crate::msg::{ChainProof, Message, OffchainRecords};
use crate::names::NameResolver;
use crate::sname::{NameLike, SName};
use crate::MessageError;
use spaces_nums::ChainProofRequest;
use spaces_protocol::slabel::SLabel;

pub struct DataUpdateRequest {
    pub handle: SName,
    pub records: Option<OffchainRecords>,
    pub delegate_records: Option<OffchainRecords>,
}

pub struct MessageBuilder {
    certs: Vec<Certificate>,
    updates: Vec<DataUpdateRequest>,
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self {
            certs: vec![],
            updates: vec![],
        }
    }

    /// Add a .spacecert chain with records.
    /// The handle name is taken from the chain's subject.
    pub fn add_handle(&mut self, chain: CertificateChain, records: OffchainRecords) {
        let handle = chain.subject().clone();
        self.certs.extend(chain.into_certs());
        self.updates.push(DataUpdateRequest {
            handle,
            records: Some(records),
            delegate_records: None,
        });
    }

    pub fn add_chain(&mut self, chain: CertificateChain) {
        self.certs.extend(chain.into_certs());
    }

    pub fn add_cert(&mut self, cert: Certificate) {
        self.certs.push(cert);
    }

    pub fn add_records(&mut self, handle: SName, records: OffchainRecords) {
        self.updates.push(DataUpdateRequest {
            handle,
            records: Some(records),
            delegate_records: None,
        });
    }

    pub fn add_update(&mut self, update: DataUpdateRequest) {
        self.updates.push(update);
    }

    /// Returns the chain proof request needed to build the message.
    ///
    /// Extracts proof keys from certificates (space, registry, commitment, num ID).
    /// For updates without a matching certificate, adds the minimum space-level keys.
    pub fn chain_proof_request(&self) -> ChainProofRequest {
        let mut req = ChainProofRequest::from_certificates(self.certs.iter());

        for update in &self.updates {
            let Some(space) = update.handle.space() else {
                continue;
            };
            req.add_space(space);
        }

        req
    }

    /// Build the message from a chain proof.
    ///
    /// Deduplicates root certificates by looking up commitment block heights
    /// from the chain proof, keeping the one with the most recent commitment.
    /// Then assembles into bundles and applies all record updates.
    pub fn build(self, chain: ChainProof) -> Result<Message, MessageError> {
        let certs = dedup_root_certs(self.certs, &chain);
        let resolver = NameResolver::from_certificates(&certs, &chain.nums);
        let mut msg = Message::try_from_certificates(chain, certs)?;

        for update in self.updates {
            let handle = resolver.flatten(&update.handle);
            if let Some(data) = update.records {
                msg.set_records(&handle, data);
            }
            if let Some(data) = update.delegate_records {
                msg.set_delegate_records(&handle, data);
            }
        }

        Ok(msg)
    }
}

impl Message {
    /// Update offchain data on an existing message.
    ///
    /// Construct a new message to update certificates.
    pub fn update(&mut self, updates: Vec<DataUpdateRequest>) {
        for update in updates {
            if let Some(data) = update.records {
                self.set_records(&update.handle, data);
            }
            if let Some(data) = update.delegate_records {
                self.set_delegate_records(&update.handle, data);
            }
        }
    }
}

/// Resolve the block height for a root certificate's receipt by looking up
/// its commitment in the chain proof's nums tree.
fn root_cert_block_height(cert: &Certificate, chain: &ChainProof) -> u32 {
    let Some(space) = cert.subject.space() else { return 0 };
    let receipt = match &cert.witness {
        Witness::Root { receipt } => receipt.as_ref(),
        _ => return 0,
    };
    let Some(receipt) = receipt else { return 0 };
    let Ok(zkc) = receipt.journal.decode::<libveritas_zk::guest::Commitment>() else { return 0 };
    chain.nums.find_commitment(&space, zkc.final_root)
        .ok()
        .flatten()
        .map(|c| c.block_height)
        .unwrap_or(0)
}

/// Deduplicate root certificates for the same space, keeping the one
/// whose receipt points to the most recent on-chain commitment.
/// Leaf certificates are passed through unchanged.
fn dedup_root_certs(certs: Vec<Certificate>, chain: &ChainProof) -> Vec<Certificate> {
    let mut best_roots: HashMap<SLabel, (Certificate, u32)> = HashMap::new();
    let mut leaves = vec![];

    for cert in certs {
        if cert.subject.label_count() != 1 {
            leaves.push(cert);
            continue;
        }
        let height = root_cert_block_height(&cert, chain);
        let space = cert.subject.space().unwrap();
        match best_roots.get(&space) {
            Some((_, existing_height)) if *existing_height >= height => continue,
            _ => { best_roots.insert(space, (cert, height)); }
        }
    }

    let mut result: Vec<Certificate> = best_roots.into_values().map(|(cert, _)| cert).collect();
    result.extend(leaves);
    result
}
