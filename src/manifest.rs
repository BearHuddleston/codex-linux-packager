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
    /// Reports a command whose vertical implementation is not present yet.
    #[must_use]
    pub fn phase_not_implemented(command: &str) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            producer: PRODUCER_IDENTIFIER,
            ok: false,
            error: ErrorDetail {
                code: "phase_not_implemented",
                message: format!("command `{command}` is not implemented in phase 0"),
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
