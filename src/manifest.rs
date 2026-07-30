//! Versioned identities and deterministic JSON encoding.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::PackagerError;

/// The only document schema accepted by this clean-room implementation.
pub const SCHEMA_VERSION: u32 = 1;

/// Identifies documents produced by the Rust clean-room implementation.
pub const PRODUCER_IDENTIFIER: &str = "io.github.bearhuddleston.codex-linux-packager.rust";

/// Identity fields carried by every persisted machine-readable document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentHeader {
    schema: u32,
    producer: String,
}

/// Machine-readable failure details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorDetail {
    code: &'static str,
    message: String,
}

/// Versioned machine-readable command failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorDocument {
    schema: u32,
    producer: &'static str,
    ok: bool,
    error: ErrorDetail,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDocumentHeader {
    schema: u32,
    producer: String,
}

impl DocumentHeader {
    /// Returns the identity for documents produced by this version.
    #[must_use]
    pub fn current() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            producer: PRODUCER_IDENTIFIER.to_owned(),
        }
    }

    /// Returns the exact document schema.
    #[must_use]
    pub const fn schema(&self) -> u32 {
        self.schema
    }

    /// Returns the exact producer identifier.
    #[must_use]
    pub fn producer(&self) -> &str {
        &self.producer
    }
}

impl ErrorDocument {
    /// Constructs a deterministic versioned command failure.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            producer: PRODUCER_IDENTIFIER,
            ok: false,
            error: ErrorDetail {
                code,
                message: message.into(),
            },
        }
    }
}

impl<'de> Deserialize<'de> for DocumentHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawDocumentHeader::deserialize(deserializer)?;
        if raw.schema != SCHEMA_VERSION {
            return Err(D::Error::custom(PackagerError::UnsupportedSchema {
                expected: SCHEMA_VERSION,
                actual: raw.schema,
            }));
        }
        if raw.producer != PRODUCER_IDENTIFIER {
            return Err(D::Error::custom(PackagerError::UnexpectedProducer {
                expected: PRODUCER_IDENTIFIER,
                actual: raw.producer,
            }));
        }

        Ok(Self {
            schema: raw.schema,
            producer: raw.producer,
        })
    }
}

/// Serializes a typed structure as one compact JSON document and a newline.
pub fn to_json_line<T: Serialize>(value: &T) -> Result<String, PackagerError> {
    let mut encoded = serde_json::to_string(value)?;
    encoded.push('\n');
    Ok(encoded)
}

/// Returns whether `value` is one real Gregorian UTC second in the canonical
/// `YYYY-MM-DDTHH:MM:SSZ` form used by signed documents.
pub(crate) fn is_canonical_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.get(19) != Some(&b'Z')
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return false;
    }

    let Some(year) = decimal(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = decimal(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = decimal(&bytes[8..10]) else {
        return false;
    };
    let Some(hour) = decimal(&bytes[11..13]) else {
        return false;
    };
    let Some(minute) = decimal(&bytes[14..16]) else {
        return false;
    };
    let Some(second) = decimal(&bytes[17..19]) else {
        return false;
    };
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_gregorian_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    year != 0 && (1..=maximum_day).contains(&day) && hour < 24 && minute < 60 && second < 60
}

fn decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        value
            .checked_mul(10)?
            .checked_add(u32::from(byte.checked_sub(b'0')?))
    })
}

const fn is_gregorian_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
