use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::str::FromStr;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{Error as DeError, SeqAccess, Visitor};
use spaces_protocol::slabel::SLabel;

/// Maximum length of a space name in bytes.
pub const MAX_SPACE_LEN: usize = 255;

/// Maximum length of a single label in bytes.
pub const MAX_LABEL_LEN: usize = 63;

/// A DNS-encoded name representing a space handle.
///
/// An `SName` stores a hierarchical name using DNS wire format encoding, where each label
/// is prefixed by its length byte and the name is terminated by a null byte.
///
/// # Display Format
///
/// When displayed as a string, an `SName` uses the format `labels@space` where:
/// - The **space** (root) appears after the `@` symbol with no dots following it
/// - **Subspace labels** appear before the `@`, separated by dots
///
/// For example, `hello.world@bitcoin` represents:
/// - `bitcoin` - the space (root label)
/// - `world` - a subspace of `bitcoin`
/// - `hello` - a label within `world`
///
/// # Wire Format
///
/// Internally, labels are stored in order with length prefixes:
/// ```text
/// \x05hello\x05world\x07bitcoin\x00
///   ^5 bytes  ^5 bytes  ^7 bytes  ^null terminator
/// ```
///
/// # Examples
///
/// ```ignore
/// use std::str::FromStr;
///
/// // Parse from display format
/// let name = SName::from_str("alice@bitcoin").unwrap();
/// assert_eq!(name.to_string(), "alice@bitcoin");
///
/// // Multi-level subspace
/// let name = SName::from_str("key.wallet@bitcoin").unwrap();
/// assert_eq!(name.to_string(), "key.wallet@bitcoin");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SName([u8; MAX_SPACE_LEN]);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(SLabel);

// Borsh implementations for SName and Label

impl BorshSerialize for SName {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.serialize(writer)
    }
}

impl BorshDeserialize for SName {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes: [u8; MAX_SPACE_LEN] = BorshDeserialize::deserialize_reader(reader)?;
        Ok(SName(bytes))
    }
}

impl BorshSerialize for Label {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Serialize as the raw bytes of the SLabel
        BorshSerialize::serialize(&self.0.as_ref().to_vec(), writer)
    }
}

impl BorshDeserialize for Label {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let slabel = SLabel::try_from(bytes.as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Label(slabel))
    }
}

impl Label {
    pub fn as_slabel(&self) -> &SLabel {
        &self.0
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = self.0.to_string_unprefixed().map_err(|_| std::fmt::Error)?;
        write!(f, "{}", s)
    }
}


/// Error type for space name parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Name is empty.
    Empty,
    /// Name exceeds maximum length of 255 bytes.
    TooLong,
    /// Label exceeds maximum length of 63 bytes.
    LabelTooLong,
    /// Missing null terminator in wire format.
    MissingNullTerminator,
    /// Invalid label length byte in wire format.
    InvalidLabelLength,
    /// Name contains invalid characters (must be lowercase alphanumeric).
    InvalidCharacter,
    /// Malformed name.
    Malformed,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Empty => write!(f, "name is empty"),
            Error::TooLong => write!(f, "name exceeds maximum length of {} bytes", MAX_SPACE_LEN),
            Error::LabelTooLong => write!(f, "label exceeds maximum length of {} bytes", MAX_LABEL_LEN),
            Error::MissingNullTerminator => write!(f, "missing null terminator"),
            Error::InvalidLabelLength => write!(f, "invalid label length byte"),
            Error::InvalidCharacter => write!(f, "invalid character (must be lowercase alphanumeric)"),
            Error::Malformed => write!(f, "malformed name structure"),
        }
    }
}

impl std::error::Error for Error {}

/// A borrowed reference to a space name.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SNameRef<'a>(pub &'a [u8]);

/// Iterator over the labels in a space name.
pub struct LabelIterator<'a>(&'a [u8]);

/// Trait for types that behave like space names.
pub trait NameLike {
    /// Returns the underlying byte representation.
    fn inner_bytes(&self) -> &[u8];

    /// Returns the wire-format bytes including the null terminator.
    fn to_bytes(&self) -> &[u8] {
        let mut len = 0;
        for label in self.iter() {
            len += label.len() + 1;
        }
        len += 1; // null byte
        &self.inner_bytes()[..len]
    }

    /// Returns `true` if this name has exactly one label.
    #[inline(always)]
    fn is_single_label(&self) -> bool {
        self.label_count() == 1
    }

    /// Returns the number of labels in this name.
    fn label_count(&self) -> usize {
        let mut count = 0;
        let mut slice = &self.inner_bytes()[..];
        while !slice.is_empty() && slice[0] != 0 {
            slice = &slice[slice[0] as usize + 1..];
            count += 1;
        }
        count
    }

    /// Returns an iterator over the labels in this name.
    #[inline(always)]
    fn iter(&self) -> LabelIterator<'_> {
        LabelIterator(&self.inner_bytes()[..])
    }
}

impl NameLike for SName {
    fn inner_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl NameLike for SNameRef<'_> {
    fn inner_bytes(&self) -> &[u8] {
        self.0
    }
}

impl SName {
    /// Returns a borrowed reference to this name.
    pub fn as_name_ref(&self) -> SNameRef<'_> {
        SNameRef(&self.0)
    }

    /// Returns the top-level space (the label after `@`).
    ///
    /// For `hello.world@bitcoin`, this returns `Some(SLabel("bitcoin"))`.
    /// Returns `None` if the name has no labels.
    pub fn space(&self) -> Option<SLabel> {
        let labels: Vec<&[u8]> = self.iter().collect();
        let last = labels.last()?;
        let s = std::str::from_utf8(last).ok()?;
        SLabel::from_str_unprefixed(s).ok()
    }

    /// Returns the subspace (the second-level label, immediately before the space).
    ///
    /// For `hello.world@bitcoin`, this returns `Some(Label("world"))`.
    /// Returns `None` if the name has fewer than two labels.
    pub fn subspace(&self) -> Option<Label> {
        let labels: Vec<&[u8]> = self.iter().collect();
        if labels.len() < 2 {
            return None;
        }
        let second_to_last = labels[labels.len() - 2];
        let s = std::str::from_utf8(second_to_last).ok()?;
        let slabel = SLabel::from_str_unprefixed(s).ok()?;
        Some(Label(slabel))
    }
}

impl SNameRef<'_> {
    /// Creates an owned copy of this name reference.
    pub fn to_owned(&self) -> SName {
        let mut owned = SName([0; MAX_SPACE_LEN]);
        owned.0[..self.0.len()].copy_from_slice(self.0);
        owned
    }
}

// Display implementations

impl Display for SName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let labels: Vec<&str> = self
            .iter()
            .map(|label| std::str::from_utf8(label).unwrap())
            .collect();

        let last_label = labels.last().unwrap();
        let all_but_last = &labels[..labels.len() - 1];
        write!(f, "{}@{}", all_but_last.join("."), last_label)
    }
}

impl Display for SNameRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

// FromStr and TryFrom implementations

impl FromStr for SName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<&str> for SName {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (subspace, space) = value
            .split_once('@')
            .ok_or(Error::Malformed)?;

        if space.is_empty() || space.contains('.') {
            return Err(Error::Malformed);
        }

        let mut space_bytes = [0; MAX_SPACE_LEN];
        let mut space_len = 0;

        for label in subspace.split('.').chain(std::iter::once(space)) {
            if space_len == 0 && label.is_empty() {
                continue; // Skip initial subspace label if empty
            }

            let label_bytes = label.as_bytes();
            let label_len = label_bytes.len();

            if label_len == 0 {
                return Err(Error::Malformed);
            }
            if label_len > MAX_LABEL_LEN {
                return Err(Error::LabelTooLong);
            }
            if space_len + label_len + 2 > MAX_SPACE_LEN {
                return Err(Error::TooLong);
            }

            if label
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() || b.is_ascii_uppercase())
            {
                return Err(Error::InvalidCharacter);
            }

            // Insert the length of the label before the label itself
            space_bytes[space_len] = label_len as u8;
            space_len += 1;

            // Copy the label into the space_bytes array
            space_bytes[space_len..space_len + label_len].copy_from_slice(label_bytes);
            space_len += label_len;
        }

        // Mark end with null byte
        space_bytes[space_len] = 0;

        Ok(SName(space_bytes))
    }
}

impl TryFrom<String> for SName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl<const N: usize> TryFrom<&[u8; N]> for SName {
    type Error = Error;

    fn try_from(value: &[u8; N]) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&Vec<u8>> for SName {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&[u8]> for SName {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let name_ref: SNameRef = value.try_into()?;
        Ok(name_ref.to_owned())
    }
}

impl<'a> TryFrom<&'a [u8]> for SNameRef<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let mut remaining = value;
        if remaining.is_empty() {
            return Err(Error::Empty);
        }
        if remaining.len() > MAX_SPACE_LEN {
            return Err(Error::TooLong);
        }

        let mut parsed_len = 0;
        loop {
            if remaining.is_empty() {
                return Err(Error::MissingNullTerminator);
            }
            let label_len = remaining[0] as usize;
            if label_len == 0 {
                parsed_len += 1;
                break;
            }
            if label_len > MAX_LABEL_LEN {
                return Err(Error::LabelTooLong);
            }
            if label_len + 1 > remaining.len() {
                return Err(Error::InvalidLabelLength);
            }
            remaining = &remaining[label_len + 1..];
            parsed_len += label_len + 1;
        }

        Ok(SNameRef(&value[..parsed_len]))
    }
}

// Iterator implementation

impl<'a> Iterator for LabelIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() || self.0[0] == 0 {
            return None;
        }

        let label_len = self.0[0] as usize;
        let (label, rest) = self.0.split_at(label_len + 1);
        self.0 = rest;
        Some(&label[1..])
    }
}

// Serde implementations

impl Serialize for SName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

struct SNameVisitorBytes;

impl<'de> Visitor<'de> for SNameVisitorBytes {
    type Value = SName;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a byte array representing an SName")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bytes = [0; MAX_SPACE_LEN];
        let mut index = 0;

        while let Some(byte) = seq.next_element()? {
            if index >= MAX_SPACE_LEN {
                return Err(serde::de::Error::invalid_length(index, &self));
            }
            bytes[index] = byte;
            index += 1;
        }

        Ok(SName(bytes))
    }
}

impl<'de> Deserialize<'de> for SName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String as Deserialize>::deserialize(deserializer)?;
            SName::from_str(&s).map_err(|e| serde::de::Error::custom(e))
        } else {
            deserializer.deserialize_seq(SNameVisitorBytes)
        }
    }
}


impl FromStr for Label {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Label(
            SLabel::from_str_unprefixed(s).map_err(|_| "invalid subspace label")?,
        ))
    }
}

impl Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            Serialize::serialize(&self.0, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String as Deserialize>::deserialize(deserializer)?;
            Label::from_str(&s).map_err(DeError::custom)
        } else {
            let lbl: SLabel = <SLabel as Deserialize>::deserialize(deserializer)?;
            Ok(Label(lbl))
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_slice() {
        assert!(SName::try_from(b"").is_err(), "Should fail on empty slice");

        assert!(
            SName::try_from(b"\x00").is_ok(),
            "Should succeed on root domain (empty space)"
        );
        assert_eq!(
            SName::try_from(b"\x00").unwrap().label_count(),
            0,
            "Root domain should have 0 labels"
        );

        assert!(
            SName::try_from(b"\x03bob").is_err(),
            "Should fail on missing null byte"
        );

        assert!(
            SName::try_from(b"\x03bob\x00").is_ok(),
            "Should succeed on single label"
        );
        assert_eq!(
            SName::try_from(b"\x03bob\x00").unwrap().label_count(),
            1,
            "Should count single label"
        );

        assert!(
            SName::try_from(b"\x03bob\x07bitcoin\x00").is_ok(),
            "Should succeed on two labels"
        );
        assert_eq!(
            SName::try_from(b"\x03bob\x07bitcoin\x00")
                .unwrap()
                .label_count(),
            2,
            "Should count two labels"
        );

        let mut max_label = vec![0x3f]; // Length byte for 63 characters
        max_label.extend_from_slice(&vec![b'a'; 63]); // 63 'a's
        max_label.push(0x00); // Null byte
        assert!(
            SName::try_from(&max_label).is_ok(),
            "Should succeed on max length label"
        );

        assert!(
            SName::try_from(b"\x03bob\x00\x03foo").is_ok(),
            "Should stop parsing at null byte"
        );
        assert_eq!(
            SName::try_from(b"\x03bob\x00\x03foo")
                .unwrap()
                .label_count(),
            1,
            "Should parse up to first null byte"
        );

        let mut long_label = vec![0x40]; // Length byte for 64 characters
        long_label.extend_from_slice(&vec![b'b'; 64]); // 64 'b's
        long_label.push(0x00); // Null byte
        assert!(
            SName::try_from(&long_label).is_err(),
            "Should fail on label too long"
        );

        assert!(
            SName::try_from(b"\x03bob\x04foo\x00").is_err(),
            "Should fail on incorrect label length byte"
        );
    }

    #[test]
    fn test_iter() {
        let space = SName::try_from(b"\x03bob\x07bitcoin\x00").unwrap();
        let mut iter = space.iter();
        assert_eq!(iter.next(), Some(b"bob" as &[u8]));
        assert_eq!(iter.next(), Some(b"bitcoin" as &[u8]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_from_string() {
        assert!(SName::from_str("").is_err(), "Should fail on empty string");
        assert!(
            SName::from_str("bitcoin").is_err(),
            "Should fail on missing @"
        );
        assert!(
            SName::from_str("@").is_err(),
            "Should fail on missing subspace"
        );
        assert!(
            SName::from_str("hey..bob@bitcoin").is_err(),
            "Should fail on empty label"
        );

        assert!(
            SName::from_str("@bitcoin").is_ok(),
            "Should succeed on single label"
        );
        assert!(
            SName::from_str("bob@bitcoin").is_ok(),
            "Should succeed on two label"
        );
        assert!(
            SName::from_str("hello.bob@bitcoin").is_ok(),
            "Should succeed on multi labels"
        );

        let example = SName::from_str("hello.bob@bitcoin").unwrap();
        assert_eq!(example.label_count(), 3, "Should count three labels");
        let mut iter = example.iter();
        assert_eq!(iter.next(), Some(b"hello" as &[u8]));
        assert_eq!(iter.next(), Some(b"bob" as &[u8]));
        assert_eq!(iter.next(), Some(b"bitcoin" as &[u8]));
        assert_eq!(iter.next(), None);
        assert_eq!(
            example.to_bytes(),
            b"\x05hello\x03bob\x07bitcoin\x00" as &[u8]
        );
    }
}
