use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;
use crate::cert::{Certificate, NumsSubtree};
use crate::Zone;
use spaces_protocol::slabel::SLabel;
use spaces_protocol::sname::{NameLike, SName, Subname};


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
                aliases.insert(zone.canonical.clone(), alias.clone());
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

    /// Set human-readable handle names on zones.
    /// `canonical` stays unchanged; `handle` gets the expanded form.
    pub fn expand_zones(&self, zones: &mut [Zone]) {
        for zone in zones {
            zone.handle = self.expand(&zone.canonical);
        }
    }
}

/// Build a 2-label SName from raw label bytes and a space SLabel.
fn build_2label(label_bytes: &[u8], space: &SLabel) -> Option<SName> {
    let label_str = std::str::from_utf8(label_bytes).ok()?;
    let label: Subname = label_str.parse().ok()?;
    SName::join(&label, space).ok()
}

/// Tracks a single name being resolved.
struct LookupEntry {
    /// Original labels left-to-right, e.g. ["pancakes", "nested1", "alice", "bitcoin"]
    labels: Vec<String>,
    /// Index of the next subspace label to resolve (moves right-to-left).
    cursor: usize,
    /// The current space for the next lookup.
    space: SLabel,
    /// Whether this entry's current handle has been fetched and has no more levels.
    done: bool,
}

impl LookupEntry {
    fn new(name: &SName) -> Option<Self> {
        let count = name.label_count();
        if count == 0 {
            return None;
        }
        let labels: Vec<String> = name.iter()
            .map(|l| std::str::from_utf8(l).unwrap_or("").to_string())
            .collect();
        let space = name.space()?;
        let done = count <= 1;
        Some(Self {
            labels,
            cursor: count.saturating_sub(2),
            space,
            done,
        })
    }

    fn current_handle(&self) -> Option<SName> {
        if self.labels.len() == 1 {
            return Some(SName::from(&self.space));
        }
        build_2label(self.labels[self.cursor].as_bytes(), &self.space)
    }

    fn advance(&mut self, alias: SLabel) {
        self.cursor -= 1;
        self.space = alias;
    }
}

struct LookupState {
    entries: Vec<LookupEntry>,
    resolver: NameResolver,
}

/// Batched iterative resolver for nested handle names.
///
/// Breaks down deep names into a sequence of 2-label lookups, batched by
/// depth level. Uses `&self` throughout for FFI compatibility.
///
/// ```text
/// let lookup = Lookup::new(vec!["pancakes.nested1.alice@bitcoin", "bob@nostr"]);
/// let batch = lookup.start();         // → ["alice@bitcoin", "bob@nostr"]
/// let zones = relay.resolveAll(batch);
/// let batch = lookup.advance(&zones); // → ["nested1#800-12-12"]
/// let zones2 = relay.resolveAll(batch);
/// let batch = lookup.advance(&zones2); // → ["pancakes#822-88-22"]
/// // ... until batch is empty
/// lookup.expand_zones(&mut all_zones);
/// ```
pub struct Lookup {
    state: Mutex<LookupState>,
}

impl Lookup {
    pub fn new(names: Vec<SName>) -> Self {
        let entries = names.iter()
            .filter_map(|n| LookupEntry::new(n))
            .collect();
        Self {
            state: Mutex::new(LookupState {
                entries,
                resolver: NameResolver::from_aliases(HashMap::new()),
            }),
        }
    }

    /// Returns the first batch of handles to look up.
    pub fn start(&self) -> Vec<SName> {
        let state = self.state.lock().unwrap();
        state.entries.iter()
            .filter_map(|e| e.current_handle())
            .collect()
    }

    /// Feed zones from a resolveAll response. Returns the next batch.
    /// Empty result means resolution is complete.
    pub fn advance(&self, zones: &[Zone]) -> Vec<SName> {
        let mut state = self.state.lock().unwrap();

        for zone in zones {
            if let Some(alias) = &zone.alias {
                state.resolver.aliases.insert(zone.canonical.clone(), alias.clone());
                state.resolver.reverse.insert(alias.clone(), zone.canonical.clone());
            }
        }

        for entry in &mut state.entries {
            if entry.done {
                continue;
            }
            let Some(handle) = entry.current_handle() else { continue };
            let Some(zone) = zones.iter().find(|z| z.canonical == handle) else { continue };
            match &zone.alias {
                Some(alias) if entry.cursor > 0 => entry.advance(alias.clone()),
                _ => entry.done = true,
            }
        }

        state.entries.iter()
            .filter(|e| !e.done)
            .filter_map(|e| e.current_handle())
            .collect()
    }

    /// Expand zone handles using the alias map accumulated during resolution.
    pub fn expand_zones(&self, zones: &mut [Zone]) {
        let state = self.state.lock().unwrap();
        state.resolver.expand_zones(zones);
    }
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
        let sname = SName::from_str(handle).unwrap();
        Zone {
            anchor: 0,
            sovereignty: crate::SovereigntyState::Sovereign,
            canonical: sname.clone(),
            handle: sname,
            alias: alias.map(|n| n.to_slabel()),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x00]),
            fallback_records: sip7::RecordSet::default(),
            records: sip7::RecordSet::default(),
            delegate: crate::ProvableOption::Unknown,
            commitment: crate::ProvableOption::Unknown,
            num_id: None,
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

    // -- lookup tests --

    #[test]
    fn lookup_2_labels_resolves_immediately() {
        let lookup = Lookup::new(vec![
            SName::from_str("alice@bitcoin").unwrap(),
        ]);
        let batch = lookup.start();
        assert_eq!(batch, vec![SName::from_str("alice@bitcoin").unwrap()]);

        // No alias needed — 2 labels, nothing to advance
        let zones = vec![make_zone("alice@bitcoin", None)];
        let next = lookup.advance(&zones);
        assert!(next.is_empty());
    }

    #[test]
    fn lookup_3_labels() {
        // nested1.alice@bitcoin requires: alice@bitcoin → #800-12-12 → nested1#800-12-12
        let lookup = Lookup::new(vec![
            SName::from_str("nested1.alice@bitcoin").unwrap(),
        ]);

        let batch = lookup.start();
        assert_eq!(batch, vec![SName::from_str("alice@bitcoin").unwrap()]);

        let zones = vec![make_zone("alice@bitcoin", Some(SNumeric::new(800, 12, 12)))];
        let next = lookup.advance(&zones);
        assert_eq!(next, vec![SName::from_str("nested1#800-12-12").unwrap()]);

        let zones2 = vec![make_zone("nested1#800-12-12", None)];
        let done = lookup.advance(&zones2);
        assert!(done.is_empty());
    }

    #[test]
    fn lookup_4_labels() {
        let lookup = Lookup::new(vec![
            SName::from_str("pancakes.nested1.alice@bitcoin").unwrap(),
        ]);

        let batch = lookup.start();
        assert_eq!(batch, vec![SName::from_str("alice@bitcoin").unwrap()]);

        let zones = vec![make_zone("alice@bitcoin", Some(SNumeric::new(800, 12, 12)))];
        let next = lookup.advance(&zones);
        assert_eq!(next, vec![SName::from_str("nested1#800-12-12").unwrap()]);

        let zones2 = vec![make_zone("nested1#800-12-12", Some(SNumeric::new(822, 88, 22)))];
        let next2 = lookup.advance(&zones2);
        assert_eq!(next2, vec![SName::from_str("pancakes#822-88-22").unwrap()]);

        let zones3 = vec![make_zone("pancakes#822-88-22", None)];
        let done = lookup.advance(&zones3);
        assert!(done.is_empty());
    }

    #[test]
    fn lookup_mixed_depths() {
        // Two names with different depths
        let lookup = Lookup::new(vec![
            SName::from_str("nested1.alice@bitcoin").unwrap(), // 3 labels
            SName::from_str("bob@nostr").unwrap(),             // 2 labels
        ]);

        let batch = lookup.start();
        assert_eq!(batch.len(), 2);
        assert!(batch.contains(&SName::from_str("alice@bitcoin").unwrap()));
        assert!(batch.contains(&SName::from_str("bob@nostr").unwrap()));

        // Both resolve. bob@nostr is done (2 labels), alice@bitcoin has alias.
        let zones = vec![
            make_zone("alice@bitcoin", Some(SNumeric::new(800, 12, 12))),
            make_zone("bob@nostr", None),
        ];
        let next = lookup.advance(&zones);
        // Only nested1#800-12-12 remains
        assert_eq!(next, vec![SName::from_str("nested1#800-12-12").unwrap()]);

        let zones2 = vec![make_zone("nested1#800-12-12", None)];
        let done = lookup.advance(&zones2);
        assert!(done.is_empty());
    }

    #[test]
    fn lookup_single_label() {
        let lookup = Lookup::new(vec![
            SName::from_str("@bitcoin").unwrap(),
        ]);

        let names = lookup.start();
        assert_eq!(names[0], SName::from_str("@bitcoin").unwrap());
        assert!(lookup.advance(&[]).is_empty());
    }

    #[test]
    fn lookup_expand_zones_at_end() {
        let lookup = Lookup::new(vec![
            SName::from_str("nested1.alice@bitcoin").unwrap(),
        ]);

        let _ = lookup.start();
        let zones = vec![make_zone("alice@bitcoin", Some(SNumeric::new(800, 12, 12)))];
        let _ = lookup.advance(&zones);

        // Now expand a zone with numeric handle
        let mut zones_to_expand = vec![
            make_zone("nested1#800-12-12", None),
        ];
        lookup.expand_zones(&mut zones_to_expand);
        assert_eq!(zones_to_expand[0].handle, SName::from_str("nested1.alice@bitcoin").unwrap());
    }
}
