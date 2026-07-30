//! Typed comparison between the latest authenticated feed metadata, the
//! reviewed runtime contract, and the last recorded engineering candidate.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::feed::{FeedInspection, ReleaseMetadata};
use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION};
use crate::release::ReleaseAssessmentScope;
use crate::runtime::RuntimeApplicationContract;

const CANDIDATE_JSON: &str = include_str!("../data/engineering-candidate.json");
const MAX_APPIMAGE_BYTES: u64 = 1024 * 1024 * 1024;

/// Application identity of the last independently assessed engineering
/// candidate. This record is informational and cannot approve publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineeringCandidateIdentity {
    /// Authenticated desktop application version.
    pub version: String,
    /// Authenticated desktop application build.
    pub build: String,
}

/// Digest-bound record of the last independently assessed local candidate.
///
/// This record is monitoring state, not payload redistribution authority or
/// release approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineeringCandidateRecord {
    /// Rust-owned document schema.
    pub schema: u32,
    /// Unambiguous producer identifier.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Exact source commit used for the assessed candidate.
    pub source_commit: String,
    /// Authenticated application identity.
    pub application: EngineeringCandidateIdentity,
    /// Exact evidence digest set from `release-readiness`.
    pub assessment_scope: ReleaseAssessmentScope,
    /// Whether the implemented engineering pipeline passed.
    pub engineering_candidate: bool,
    /// Must remain false until every independent publication gate is cleared.
    pub stable_publication_permitted: bool,
    /// Explicit non-publication disposition.
    pub release_status: String,
}

/// Next action established by comparing feed, contract, and candidate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamAction {
    /// The latest feed item, reviewed contract, and candidate agree.
    Current,
    /// The feed changed and the independently pinned contracts require review.
    ReviewContractUpdate,
    /// The contract is current but no matching candidate has been recorded.
    RebuildCandidate,
}

/// Deterministic schema-1 upstream monitoring result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamStatusReport {
    /// Rust-owned document schema.
    pub schema: u32,
    /// Unambiguous producer identifier.
    pub producer: &'static str,
    /// Stable document kind.
    pub kind: &'static str,
    /// SHA-256 of the exact feed bytes.
    pub feed_sha256: String,
    /// Latest authoritative feed item.
    pub latest_release: ReleaseMetadata,
    /// Reviewed application identity accepted by the runtime contract.
    pub contracted_application: RuntimeApplicationContract,
    /// Last independently assessed engineering candidate.
    pub engineering_candidate: EngineeringCandidateIdentity,
    /// Required next action.
    pub action: UpstreamAction,
    /// Whether independently pinned contracts must be reviewed and updated.
    pub contract_update_required: bool,
    /// Whether the desired latest application lacks a matching candidate.
    pub candidate_rebuild_required: bool,
    /// Whether automation may rebuild without changing reviewed contracts.
    pub automatic_rebuild_permitted: bool,
    /// Truthful explanation of the required action.
    pub required_action: &'static str,
}

/// Invalid or incomplete upstream comparison inputs.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UpstreamError {
    /// A typed input has an invalid identity or envelope.
    #[error("invalid upstream status input: {0}")]
    Invalid(String),
}

/// Parses and validates the embedded last-candidate monitoring record.
pub fn engineering_candidate_record() -> Result<EngineeringCandidateRecord, UpstreamError> {
    let record: EngineeringCandidateRecord = serde_json::from_str(CANDIDATE_JSON)
        .map_err(|error| UpstreamError::Invalid(error.to_string()))?;
    if record.schema != SCHEMA_VERSION
        || record.producer != PRODUCER_IDENTIFIER
        || record.kind != "engineering_candidate_record"
    {
        return Err(UpstreamError::Invalid(
            "engineering candidate document identity differs".to_owned(),
        ));
    }
    if record.source_commit.len() != 40 || !is_lower_hex(&record.source_commit) {
        return Err(UpstreamError::Invalid(
            "engineering candidate source commit is invalid".to_owned(),
        ));
    }
    validate_application_identity(
        &record.application.version,
        &record.application.build,
        "engineering candidate",
    )?;
    for (digest, label) in [
        (
            &record.assessment_scope.stage_provenance_sha256,
            "stage provenance",
        ),
        (
            &record.assessment_scope.native_manifest_sha256,
            "native manifest",
        ),
        (
            &record.assessment_scope.runtime_manifest_sha256,
            "runtime manifest",
        ),
        (
            &record.assessment_scope.appdir_manifest_sha256,
            "AppDir manifest",
        ),
        (
            &record.assessment_scope.appimage_provenance_sha256,
            "AppImage provenance",
        ),
        (&record.assessment_scope.artifact_sha256, "AppImage"),
        (&record.assessment_scope.cargo_lock_sha256, "Cargo.lock"),
    ] {
        if digest.len() != 64 || !is_lower_hex(digest) {
            return Err(UpstreamError::Invalid(format!(
                "engineering candidate {label} digest is invalid"
            )));
        }
    }
    if record.assessment_scope.artifact_bytes == 0
        || record.assessment_scope.artifact_bytes > MAX_APPIMAGE_BYTES
        || !record.engineering_candidate
        || record.stable_publication_permitted
        || record.release_status != "not_release_approved_do_not_publish"
    {
        return Err(UpstreamError::Invalid(
            "engineering candidate disposition is invalid".to_owned(),
        ));
    }
    Ok(record)
}

/// Compares the latest feed item with the reviewed application contract and
/// last candidate without allowing the feed to authorize its own dependencies.
pub fn assess_upstream_status(
    inspection: &FeedInspection,
    contract: &RuntimeApplicationContract,
    candidate: &EngineeringCandidateIdentity,
) -> Result<UpstreamStatusReport, UpstreamError> {
    validate_inputs(inspection, contract, candidate)?;
    let latest = inspection
        .releases
        .first()
        .ok_or_else(|| UpstreamError::Invalid("feed contains no releases".to_owned()))?;

    let contract_matches = latest.version == contract.version && latest.build == contract.build;
    let candidate_matches =
        candidate.version == contract.version && candidate.build == contract.build;

    let (action, required_action) = if !contract_matches {
        (
            UpstreamAction::ReviewContractUpdate,
            "Authenticate the new artifact, reconcile every independently pinned runtime/native input, and review the contract change before rebuilding.",
        )
    } else if !candidate_matches {
        (
            UpstreamAction::RebuildCandidate,
            "Rebuild from fresh roots under the current reviewed contracts and run release-readiness over the exact result.",
        )
    } else {
        (
            UpstreamAction::Current,
            "No action: the latest feed item, reviewed contract, and recorded engineering candidate agree.",
        )
    };

    Ok(UpstreamStatusReport {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "upstream_status",
        feed_sha256: inspection.feed_sha256.clone(),
        latest_release: latest.clone(),
        contracted_application: contract.clone(),
        engineering_candidate: candidate.clone(),
        action,
        contract_update_required: !contract_matches,
        candidate_rebuild_required: !contract_matches || !candidate_matches,
        automatic_rebuild_permitted: action == UpstreamAction::RebuildCandidate,
        required_action,
    })
}

fn validate_inputs(
    inspection: &FeedInspection,
    contract: &RuntimeApplicationContract,
    candidate: &EngineeringCandidateIdentity,
) -> Result<(), UpstreamError> {
    if inspection.schema != SCHEMA_VERSION
        || inspection.producer != PRODUCER_IDENTIFIER
        || inspection.kind != "feed_inspection"
        || inspection.channel_title != "Codex"
        || inspection.feed_sha256.len() != 64
        || !inspection
            .feed_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UpstreamError::Invalid(
            "feed inspection identity differs".to_owned(),
        ));
    }
    for (version, build, label) in [
        (&contract.version, &contract.build, "runtime contract"),
        (
            &candidate.version,
            &candidate.build,
            "engineering candidate",
        ),
    ] {
        validate_application_identity(version, build, label)?;
    }
    Ok(())
}

fn validate_application_identity(
    version: &str,
    build: &str,
    label: &str,
) -> Result<(), UpstreamError> {
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || build.is_empty()
        || build.len() > 32
        || !build.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(UpstreamError::Invalid(format!(
            "{label} application identity is invalid"
        )));
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
