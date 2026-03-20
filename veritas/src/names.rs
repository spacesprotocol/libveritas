use std::collections::HashMap;
use std::str::FromStr;
use crate::cert::{Certificate, NumsSubtree};
use crate::sname::{NameLike, SName};
use crate::Zone;
use spaces_protocol::slabel::SLabel;

/// Bidirectional name resolver for space handle hierarchies.
///
/// Handles the mapping between human-readable hierarchical names
/// (e.g., `pancakes.nested1.alice@bitcoin`) and their flat on-chain
/// 2-label form (e.g., `pancakes#822-88-22`).
///
/// Uses the same alias map (`SName → SLabel`) in both directions:
/// - `flatten()`: deep human name → 2-label numeric (for building messages)
/// - `expand()`: 2-label numeric → deep human name (for displaying zones)
pub struct NameResolver {
    /// Forward map: 2-label handle → numeric alias.
    /// e.g., `alice@bitcoin` → `#800-12-12`
    aliases: HashMap<SName, SLabel>,
    /// Reverse map: numeric SLabel → human-readable handle.
    /// e.g., `#800-12-12` → `alice@bitcoin`
    reverse: HashMap<SLabel, SName>,
}

impl NameResolver {
    fn from_aliases(aliases: HashMap<SName, SLabel>) -> Self {
        let reverse = aliases.iter()
            .map(|(handle, numeric)| (numeric.clone(), handle.clone()))
            .collect();
        Self { aliases, reverse }
    }

    /// Build from certificates and the nums tree (for builder use).
    ///
    /// For each leaf certificate, looks up the genesis_spk in the nums tree
    /// to find the numeric alias (if any).
    pub fn from_certificates(certs: &[Certificate], nums: &NumsSubtree) -> Self {
        let mut aliases = HashMap::new();
        for cert in certs {
            let Some(genesis_spk) = cert.genesis_spk() else { continue };
            if cert.subject.space().is_none() { continue };
            let Ok(Some(numout)) = nums.find_num(genesis_spk) else { continue };
            aliases.insert(cert.subject.clone(), numout.num.name.to_slabel());
        }
        Self::from_aliases(aliases)
    }

    /// Build from verified zones (for post-verification use).
    ///
    /// Extracts aliases from zones that have a numeric alias set.
    pub fn from_zones(zones: &[Zone]) -> Self {
        let mut aliases = HashMap::new();
        for zone in zones {
            if let Some(alias) = &zone.alias {
                aliases.insert(zone.handle.clone(), alias.clone());
            }
        }
        Self::from_aliases(aliases)
    }

    /// Flatten a deep name to its 2-label form.
    ///
    /// `pancakes.nested1.alice@bitcoin` → `pancakes#822-88-22`
    ///
    /// Returns the name unchanged if already 1-2 labels or resolution fails.
    pub fn flatten(&self, name: &SName) -> SName {
        let count = name.label_count();
        if count <= 2 {
            return name.clone();
        }

        let labels: Vec<&[u8]> = name.iter().collect();
        let Some(space) = name.space() else { return name.clone() };

        let mut current = match build_2label(labels[count - 2], &space) {
            Some(n) => n,
            None => return name.clone(),
        };

        for i in (0..count - 2).rev() {
            let alias = match self.aliases.get(&current) {
                Some(a) => a,
                None => return name.clone(),
            };
            current = match build_2label(labels[i], alias) {
                Some(n) => n,
                None => return name.clone(),
            };
        }

        current
    }

    /// Expand a 2-label numeric name to its human-readable form.
    ///
    /// `nested1#800-12-12` → `nested1.alice@bitcoin`
    ///
    /// Returns the name unchanged if the space is not numeric or resolution fails.
    pub fn expand(&self, name: &SName) -> SName {
        let count = name.label_count();
        if count != 2 {
            return name.clone();
        }

        let Some(space) = name.space() else { return name.clone() };
        if !space.is_numeric() {
            return name.clone();
        }

        let Some(subspace) = name.subspace() else { return name.clone() };
        let sub_str = subspace.to_string();

        // Resolve the numeric space to a human-readable parent handle,
        // recursively expanding if the parent is also numeric.
        let parent = match self.reverse.get(&space) {
            Some(p) => self.expand(p),
            None => return name.clone(),
        };

        // Prepend our subspace label to the expanded parent.
        let expanded = format!("{}.{}", sub_str, parent);
        SName::from_str(&expanded).unwrap_or_else(|_| name.clone())
    }

    /// Expand zone handles in place.
    pub fn expand_zones(&self, zones: &mut [Zone]) {
        for zone in zones {
            zone.handle = self.expand(&zone.handle);
        }
    }
}

/// Build a 2-label SName from raw label bytes and a space SLabel.
fn build_2label(label_bytes: &[u8], space: &SLabel) -> Option<SName> {
    let label_str = std::str::from_utf8(label_bytes).ok()?;
    let label: crate::sname::Label = label_str.parse().ok()?;
    SName::join(&label, space).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{HandleSubtree, KeyHash, Witness};
    use spacedb::Sha256Hasher;
    use spacedb::subtree::{SubTree, ValueOrHash};
    use spacedb::NodeHasher;
    use spaces_nums::{Num, NumOut};
    use spaces_nums::num_id::NumId;
    use spaces_nums::snumeric::SNumeric;
    use spaces_protocol::bitcoin::ScriptBuf;
    use std::str::FromStr;

    /// Create a fake genesis script pubkey from a seed byte.
    fn fake_spk(seed: u8) -> ScriptBuf {
        let mut bytes = vec![0x51, 0x20]; // OP_1 + push 32 bytes
        bytes.extend_from_slice(&[seed; 32]);
        ScriptBuf::from_bytes(bytes)
    }

    /// Insert a NumOut into the subtree for a given genesis_spk with a specific numeric alias.
    fn insert_num(tree: &mut SubTree<Sha256Hasher>, genesis_spk: &ScriptBuf, numeric: SNumeric) {
        let num_id = NumId::from_spk::<KeyHash>(genesis_spk.clone());
        let numout = NumOut {
            n: 0,
            num: Num {
                id: num_id,
                name: numeric,
                data: None,
                last_update: 0,
            },
            value: Default::default(),
            script_pubkey: genesis_spk.clone(),
        };
        // Use the num_id as the key — find_num scans values so key doesn't matter
        // but we need a unique key per entry.
        let key = Sha256Hasher::hash(genesis_spk.as_bytes());
        let value = borsh::to_vec(&numout).expect("serialize numout");
        tree.insert(key, ValueOrHash::Value(value)).expect("insert");
    }

    /// Create a leaf certificate for a handle with the given genesis_spk.
    fn leaf_cert(name: &str, genesis_spk: ScriptBuf) -> Certificate {
        Certificate::new(
            SName::from_str(name).expect("valid name"),
            Witness::Leaf {
                genesis_spk,
                handles: HandleSubtree::empty(),
                signature: None,
            },
        )
    }

    #[test]
    fn flatten_passthrough_short_names() {
        let flattener = NameResolver::from_aliases(HashMap::new());

        let root = SName::from_str("@bitcoin").unwrap();
        assert_eq!(flattener.flatten(&root), root);

        let two = SName::from_str("alice@bitcoin").unwrap();
        assert_eq!(flattener.flatten(&two), two);
    }

    #[test]
    fn flatten_3_labels() {
        // alice@bitcoin has num alias #800-12-12
        let alice_spk = fake_spk(1);

        let mut tree = SubTree::<Sha256Hasher>::empty();
        insert_num(&mut tree, &alice_spk, SNumeric::new(800, 12, 12));
        let nums = NumsSubtree(tree);

        let certs = vec![leaf_cert("alice@bitcoin", alice_spk)];
        let flattener = NameResolver::from_certificates(&certs, &nums);

        let deep = SName::from_str("nested1.alice@bitcoin").unwrap();
        let flat = flattener.flatten(&deep);
        assert_eq!(flat, SName::from_str("nested1#800-12-12").unwrap());
    }

    #[test]
    fn flatten_4_labels() {
        // alice@bitcoin → #800-12-12
        // nested1#800-12-12 → #822-88-22
        let alice_spk = fake_spk(1);
        let nested1_spk = fake_spk(2);

        let mut tree = SubTree::<Sha256Hasher>::empty();
        insert_num(&mut tree, &alice_spk, SNumeric::new(800, 12, 12));
        insert_num(&mut tree, &nested1_spk, SNumeric::new(822, 88, 22));
        let nums = NumsSubtree(tree);

        let certs = vec![
            leaf_cert("alice@bitcoin", alice_spk),
            leaf_cert("nested1#800-12-12", nested1_spk),
        ];
        let flattener = NameResolver::from_certificates(&certs, &nums);

        let deep = SName::from_str("pancakes.nested1.alice@bitcoin").unwrap();
        let flat = flattener.flatten(&deep);
        assert_eq!(flat, SName::from_str("pancakes#822-88-22").unwrap());
    }

    #[test]
    fn flatten_missing_alias_returns_original() {
        let nums = NumsSubtree(SubTree::<Sha256Hasher>::empty());
        let flattener = NameResolver::from_certificates(&[], &nums);

        let deep = SName::from_str("pancakes.nested1.alice@bitcoin").unwrap();
        assert_eq!(flattener.flatten(&deep), deep);
    }

    fn make_zone(handle: &str, alias: Option<SNumeric>) -> Zone {
        use spaces_protocol::bitcoin::ScriptBuf;
        Zone {
            anchor: 0,
            sovereignty: crate::SovereigntyState::Sovereign,
            handle: SName::from_str(handle).unwrap(),
            alias: alias.map(|n| n.to_slabel()),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x00]),
            fallback_records: None,
            records: None,
            delegate: crate::ProvableOption::Unknown,
            commitment: crate::ProvableOption::Unknown,
        }
    }

    #[test]
    fn expand_non_numeric_unchanged() {
        let zones = vec![make_zone("alice@bitcoin", Some(SNumeric::new(800, 12, 12)))];
        let flattener = NameResolver::from_zones(&zones);

        let name = SName::from_str("alice@bitcoin").unwrap();
        assert_eq!(flattener.expand(&name), name);
    }

    #[test]
    fn expand_one_level() {
        let zones = vec![make_zone("alice@bitcoin", Some(SNumeric::new(800, 12, 12)))];
        let flattener = NameResolver::from_zones(&zones);

        let flat = SName::from_str("nested1#800-12-12").unwrap();
        let expanded = flattener.expand(&flat);
        assert_eq!(expanded, SName::from_str("nested1.alice@bitcoin").unwrap());
    }

    #[test]
    fn expand_two_levels() {
        let zones = vec![
            make_zone("alice@bitcoin", Some(SNumeric::new(800, 12, 12))),
            make_zone("nested1#800-12-12", Some(SNumeric::new(822, 88, 22))),
        ];
        let flattener = NameResolver::from_zones(&zones);

        let flat = SName::from_str("pancakes#822-88-22").unwrap();
        let expanded = flattener.expand(&flat);
        assert_eq!(expanded, SName::from_str("pancakes.nested1.alice@bitcoin").unwrap());
    }

    #[test]
    fn expand_missing_alias_returns_original() {
        let flattener = NameResolver::from_zones(&[]);

        let flat = SName::from_str("nested1#800-12-12").unwrap();
        assert_eq!(flattener.expand(&flat), flat);
    }
}
