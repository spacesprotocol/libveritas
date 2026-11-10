//! Spaces handle syntax, following `spaces_protocol::sname` rules:
//! `label@space`, where the part before `@` may be several
//! dot-separated labels. Each label is 1-62 chars of `a-z 0-9 -`, with no
//! leading, trailing or doubled hyphen (except an `xn--` punycode prefix).
//! Numeric `#block-tx-vout` labels aren't accepted here, and neither are
//! top-level spaces (`@bitcoin`): only handles can be cross-verified.

use std::fmt;

pub const MAX_LABEL_LEN: usize = 62;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handle(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleError {
    Empty,
    MissingAt,
    EmptyLabel,
    LabelTooLong,
    InvalidCharacter,
    NotCanonical,
    /// A top-level space (`@bitcoin`), which can't be cross-verified.
    TopLevelSpace,
}

impl fmt::Display for HandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HandleError::Empty => "handle is empty",
            HandleError::MissingAt => "handle must contain '@'",
            HandleError::EmptyLabel => "handle has an empty label",
            HandleError::LabelTooLong => "label exceeds 62 characters",
            HandleError::InvalidCharacter => "invalid character in handle",
            HandleError::NotCanonical => "handle is not in canonical (lowercase) form",
            HandleError::TopLevelSpace => "top-level spaces can't be cross-verified",
        })
    }
}

impl std::error::Error for HandleError {}

fn check_label(label: &str) -> Result<(), HandleError> {
    if label.is_empty() {
        return Err(HandleError::EmptyLabel);
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(HandleError::LabelTooLong);
    }
    let body = match label.strip_prefix("xn--") {
        Some(rest) if !rest.is_empty() => rest,
        _ => label,
    };
    let b = body.as_bytes();
    if b[0] == b'-' || b[b.len() - 1] == b'-' || body.contains("--") {
        return Err(HandleError::InvalidCharacter);
    }
    if !b
        .iter()
        .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(HandleError::InvalidCharacter);
    }
    Ok(())
}

impl Handle {
    /// Parse user input: trims whitespace and lowercases ASCII.
    pub fn parse(input: &str) -> Result<Self, HandleError> {
        Self::parse_canonical(&input.trim().to_ascii_lowercase())
    }

    /// Parse a string that must already be canonical (used when decoding
    /// signed bytes, so one handle has exactly one encoding).
    pub fn parse_canonical(s: &str) -> Result<Self, HandleError> {
        if s.is_empty() {
            return Err(HandleError::Empty);
        }
        if s.bytes().any(|c| c.is_ascii_uppercase()) {
            return Err(HandleError::NotCanonical);
        }
        let at = s.find('@').ok_or(HandleError::MissingAt)?;
        let (sub, space) = (&s[..at], &s[at + 1..]);
        if space.contains('@') || space.contains('.') {
            return Err(HandleError::InvalidCharacter);
        }
        check_label(space)?;
        if sub.is_empty() {
            return Err(HandleError::TopLevelSpace);
        }
        for label in sub.split('.') {
            check_label(label)?;
        }
        Ok(Handle(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid() {
        for h in [
            "alice@bitcoin",
            "pay.alice@bitcoin",
            "a-b@x1",
            "xn--80ak6aa92e@bitcoin",
        ] {
            Handle::parse(h).unwrap_or_else(|e| panic!("{h}: {e}"));
        }
        assert_eq!(
            Handle::parse("  Alice@Bitcoin ").unwrap().as_str(),
            "alice@bitcoin"
        );
        assert_eq!(Handle::parse("@bitcoin"), Err(HandleError::TopLevelSpace));
    }

    #[test]
    fn invalid() {
        for h in [
            "",
            "alice",
            "alice@",
            "@",
            "alice@bit.coin",
            "a@b@c",
            "-a@bitcoin",
            "a-@bitcoin",
            "a--b@bitcoin",
            "al ice@bitcoin",
            "alice_1@bitcoin",
            "alice@bitcoin!",
            ".a@bitcoin",
        ] {
            assert!(Handle::parse(h).is_err(), "{h} should be rejected");
        }
        assert_eq!(
            Handle::parse_canonical("Alice@bitcoin"),
            Err(HandleError::NotCanonical)
        );
        assert_eq!(
            Handle::parse(&format!("{}@bitcoin", "a".repeat(63))),
            Err(HandleError::LabelTooLong)
        );
    }
}
