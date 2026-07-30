//! Typed library errors.

use thiserror::Error;

/// Failures produced by packaging and validation primitives.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PackagerError {
    /// A persisted document does not use the one accepted schema.
    #[error("unsupported document schema {actual}; expected exactly {expected}")]
    UnsupportedSchema {
        /// The only schema this build accepts.
        expected: u32,
        /// The schema found in the input.
        actual: u32,
    },

    /// A persisted document was created by another implementation.
    #[error("unexpected document producer {actual:?}; expected exactly {expected:?}")]
    UnexpectedProducer {
        /// The only producer identifier this build accepts.
        expected: &'static str,
        /// The producer identifier found in the input.
        actual: String,
    },

    /// A typed structure could not be encoded as JSON.
    #[error("failed to encode JSON: {0}")]
    Json(#[from] serde_json::Error),
}
