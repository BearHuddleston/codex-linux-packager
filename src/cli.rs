//! Command-line contract shared by the binary and integration tests.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

/// Display backends accepted by genuine packaged launch tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LaunchBackendArgument {
    /// Native Wayland.
    Wayland,
    /// X11 or XWayland.
    X11,
}

/// Feed-bound inputs required to authenticate one downloaded artifact.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct ArtifactArguments {
    /// Path to the complete downloaded ZIP artifact.
    #[arg(long, value_name = "ZIP")]
    pub artifact: PathBuf,
    /// Canonical Sparkle Ed25519 signature over the complete ZIP.
    #[arg(long, value_name = "BASE64")]
    pub signature: String,
    /// Exact complete byte length declared by the feed.
    #[arg(long, value_name = "BYTES")]
    pub length: u64,
    /// Exact short version declared by the feed.
    #[arg(long, value_name = "VERSION")]
    pub version: String,
    /// Exact build version declared by the feed.
    #[arg(long, value_name = "BUILD")]
    pub build: String,
}

/// Auditable Linux x86_64 packaging and validation.
#[derive(Debug, Parser)]
#[command(
    name = "codex-linux-packager",
    version,
    about,
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Packaging phase to execute.
    #[command(subcommand)]
    pub command: PackagingCommand,
}

/// Public packaging command concepts.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum PackagingCommand {
    /// Inspect release metadata from the Codex Sparkle feed.
    Inspect {
        /// Inspect a bounded local XML fixture instead of using the network.
        #[arg(long, value_name = "XML")]
        fixture: Option<PathBuf>,
    },
    /// Compare the latest feed release with reviewed contract and candidate state.
    CheckUpstream {
        /// Inspect a bounded local XML fixture instead of using the network.
        #[arg(long, value_name = "XML")]
        fixture: Option<PathBuf>,
    },
    /// Download and authenticate one exact feed-selected desktop artifact.
    AcquireArtifact {
        /// Exact official artifact URL emitted by `inspect`.
        #[arg(long, value_name = "HTTPS_URL")]
        url: String,
        /// Canonical Sparkle Ed25519 signature over the complete ZIP.
        #[arg(long, value_name = "BASE64")]
        signature: String,
        /// Exact complete byte length declared by the feed.
        #[arg(long, value_name = "BYTES")]
        length: u64,
        /// Exact short version declared by the feed.
        #[arg(long, value_name = "VERSION")]
        version: String,
        /// Exact build version declared by the feed.
        #[arg(long, value_name = "BUILD")]
        build: String,
        /// New authenticated artifact path published with no replacement.
        #[arg(long, value_name = "ZIP")]
        output: PathBuf,
    },
    /// Authenticate and inspect a downloaded desktop artifact.
    InspectArtifact {
        /// Exact feed-derived artifact contract.
        #[command(flatten)]
        artifact: ArtifactArguments,
    },
    /// Authenticate and stage the narrow permitted source set.
    Stage {
        /// Exact feed-derived artifact contract.
        #[command(flatten)]
        artifact: ArtifactArguments,
        /// New generation directory published with no replacement.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
    },
    /// Extract authenticated staged inputs for a later phase.
    Extract {
        /// Authenticated schema-1 stage generation.
        #[arg(long, value_name = "DIRECTORY")]
        stage: PathBuf,
        /// New extraction directory published with no replacement.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
    },
    /// Rebuild required native modules for the target Electron ABI.
    BuildNative {
        /// Authenticated schema-1 stage generation.
        #[arg(long, value_name = "DIRECTORY")]
        stage: PathBuf,
        /// Pinned official Electron Linux x64 ZIP.
        #[arg(long, value_name = "ZIP")]
        electron_zip: PathBuf,
        /// Pinned official Electron header tarball.
        #[arg(long, value_name = "TAR.GZ")]
        electron_headers: PathBuf,
        /// npm content-addressed cache.
        #[arg(long, value_name = "DIRECTORY")]
        npm_cache: PathBuf,
        /// New private retained build directory.
        #[arg(long, value_name = "DIRECTORY")]
        work: PathBuf,
        /// New verified native output generation.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
        /// Explicitly permit npm registry access; omitted means offline.
        #[arg(long)]
        allow_network: bool,
        /// Absolute host Node.js executable.
        #[arg(long, value_name = "PROGRAM", default_value = "/usr/bin/node")]
        node: PathBuf,
        /// Absolute host npm executable.
        #[arg(long, value_name = "PROGRAM")]
        npm: PathBuf,
        /// OCI runtime used with the exact digest-addressed build image.
        #[arg(long, value_name = "PROGRAM", default_value = "/usr/bin/docker")]
        oci_runtime: PathBuf,
        /// Independently recorded SHA-256 of the OCI runtime executable.
        #[arg(long, value_name = "HEX")]
        oci_runtime_sha256: String,
        /// Optional noninteractive sudo executable used only to launch the OCI runtime.
        #[arg(long, value_name = "PROGRAM", requires = "sudo_sha256")]
        sudo_program: Option<PathBuf>,
        /// Independently recorded SHA-256 of the optional sudo executable.
        #[arg(long, value_name = "HEX", requires = "sudo_program")]
        sudo_sha256: Option<String>,
    },
    /// Assemble the pinned Linux x86_64 Electron runtime.
    AssembleRuntime {
        /// Authenticated schema-1 stage generation.
        #[arg(long, value_name = "DIRECTORY")]
        stage: PathBuf,
        /// Verified native output generation.
        #[arg(long, value_name = "DIRECTORY")]
        native: PathBuf,
        /// Independently recorded SHA-256 of the native manifest.
        #[arg(long, value_name = "HEX")]
        native_manifest_sha256: String,
        /// Pinned official Electron Linux x64 ZIP.
        #[arg(long, value_name = "ZIP")]
        electron_zip: PathBuf,
        /// Pinned official version-matched Codex package.
        #[arg(long, value_name = "TAR.GZ")]
        codex_package: PathBuf,
        /// New runtime generation published with no replacement.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
    },
    /// Construct a deterministic AppDir.
    BuildAppdir {
        /// Published Linux x86_64 runtime generation.
        #[arg(long, value_name = "DIRECTORY")]
        runtime: PathBuf,
        /// Independently recorded SHA-256 of the runtime manifest.
        #[arg(long, value_name = "HEX")]
        runtime_manifest_sha256: String,
        /// Release-built Linux x86_64 updater executable.
        #[arg(long, value_name = "PROGRAM")]
        updater: PathBuf,
        /// Independently recorded SHA-256 of the updater executable.
        #[arg(long, value_name = "HEX")]
        updater_sha256: String,
        /// Explicit normalized Unix timestamp for the complete AppDir.
        #[arg(long, value_name = "SECONDS")]
        source_date_epoch: i64,
        /// New AppDir path published with no replacement.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
    },
    /// Construct and verify a deterministic AppImage.
    PackAppimage {
        /// First deterministic AppDir.
        #[arg(long, value_name = "DIRECTORY")]
        appdir: PathBuf,
        /// Independently recorded SHA-256 of the first AppDir manifest.
        #[arg(long, value_name = "HEX")]
        appdir_manifest_sha256: String,
        /// Independently constructed AppDir under another root.
        #[arg(long, value_name = "DIRECTORY")]
        reproduction_appdir: PathBuf,
        /// Independently recorded SHA-256 of the second AppDir manifest.
        #[arg(long, value_name = "HEX")]
        reproduction_appdir_manifest_sha256: String,
        /// Exact stable-tag appimagetool AppImage.
        #[arg(long, value_name = "APPIMAGE")]
        appimagetool: PathBuf,
        /// Exact stable-tag Type-2 runtime.
        #[arg(long, value_name = "ELF")]
        type2_runtime: PathBuf,
        /// Bubblewrap executable used for network isolation.
        #[arg(long, value_name = "PROGRAM", default_value = "/usr/bin/bwrap")]
        bubblewrap: PathBuf,
        /// Independently recorded SHA-256 of bubblewrap.
        #[arg(long, value_name = "HEX")]
        bubblewrap_sha256: String,
        /// GNU readelf executable used for complete ELF audits.
        #[arg(long, value_name = "PROGRAM", default_value = "/usr/bin/readelf")]
        readelf: PathBuf,
        /// Independently recorded SHA-256 of readelf.
        #[arg(long, value_name = "HEX")]
        readelf_sha256: String,
        /// OCI runtime used for the controlled older-glibc launch.
        #[arg(long, value_name = "PROGRAM", default_value = "/usr/bin/docker")]
        oci_runtime: PathBuf,
        /// Independently recorded SHA-256 of the OCI runtime executable.
        #[arg(long, value_name = "HEX")]
        oci_runtime_sha256: String,
        /// Optional noninteractive sudo executable used only to launch the OCI runtime.
        #[arg(long, value_name = "PROGRAM", requires = "sudo_sha256")]
        sudo_program: Option<PathBuf>,
        /// Independently recorded SHA-256 of the optional sudo executable.
        #[arg(long, value_name = "HEX", requires = "sudo_program")]
        sudo_sha256: Option<String>,
        /// Independently pinned local OCI image ID for the older-glibc launch.
        #[arg(long, value_name = "SHA256:HEX")]
        older_glibc_image_id: String,
        /// Required genuine packaged launch backend; pass once for each backend.
        #[arg(long, value_enum, action = ArgAction::Append, required = true)]
        launch_backend: Vec<LaunchBackendArgument>,
        /// New output generation containing the AppImage and provenance.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
    },
    /// Generate a private Ed25519 update-signing seed and emit only its public identity.
    GenerateUpdateKey {
        /// New absolute mode-0600 raw private seed path, normally beneath ignored `work/`.
        #[arg(long, value_name = "RAW_KEY")]
        private_key: PathBuf,
    },
    /// Sign one verified AppImage and publish its pinned schema-1 update manifest.
    SignUpdate {
        /// Complete verified AppImage emitted by `pack-appimage`.
        #[arg(long, value_name = "APPIMAGE")]
        appimage: PathBuf,
        /// Canonical provenance emitted beside the AppImage.
        #[arg(long, value_name = "JSON")]
        provenance: PathBuf,
        /// Raw 32-byte mode-0600 release-signing seed.
        #[arg(long, value_name = "RAW_KEY")]
        private_key: PathBuf,
        /// Exact 40-character source commit used for the release.
        #[arg(long, value_name = "HEX")]
        source_commit: String,
        /// Explicit UTC timestamp such as `2026-07-30T18:00:00Z`.
        #[arg(long, value_name = "RFC3339")]
        published_at: String,
        /// New signed update-manifest path.
        #[arg(long, value_name = "JSON")]
        output: PathBuf,
    },
    /// Prepare deterministic signed release evidence without publishing a release.
    PrepareRelease {
        /// Exact verified Linux x86_64 Type-2 AppImage.
        #[arg(long, value_name = "APPIMAGE")]
        appimage: PathBuf,
        /// Canonical AppImage provenance emitted by `pack-appimage`.
        #[arg(long, value_name = "JSON")]
        provenance: PathBuf,
        /// Canonical signed update manifest emitted by `sign-update`.
        #[arg(long, value_name = "JSON")]
        update_manifest: PathBuf,
        /// Canonical engineering release-readiness assessment.
        #[arg(long, value_name = "JSON")]
        release_readiness: PathBuf,
        /// Canonical first AppDir manifest consumed by AppImage construction.
        #[arg(long, value_name = "JSON")]
        appdir_manifest: PathBuf,
        /// Exact Cargo.lock from the assessed source tree.
        #[arg(long, value_name = "LOCKFILE")]
        cargo_lock: PathBuf,
        /// JSON from pinned `cargo deny list --format json --layout crate`.
        #[arg(long, value_name = "JSON")]
        cargo_license_report: PathBuf,
        /// Raw 32-byte mode-0600 release-signing seed.
        #[arg(long, value_name = "RAW_KEY")]
        private_key: PathBuf,
        /// Exact 40-character source commit used for the release.
        #[arg(long, value_name = "HEX")]
        source_commit: String,
        /// Exact 40-character Git source tree used for the release.
        #[arg(long, value_name = "HEX")]
        source_tree: String,
        /// Explicit canonical UTC timestamp such as `2026-07-30T18:00:00Z`.
        #[arg(long, value_name = "RFC3339")]
        created_at: String,
        /// New release-evidence generation published with no replacement.
        #[arg(long, value_name = "DIRECTORY")]
        output: PathBuf,
    },
    /// Keylessly reverify signed release evidence and exact external assets.
    VerifyRelease {
        /// Four-file release-evidence generation.
        #[arg(long, value_name = "DIRECTORY")]
        evidence: PathBuf,
        /// Exact verified Linux x86_64 Type-2 AppImage.
        #[arg(long, value_name = "APPIMAGE")]
        appimage: PathBuf,
        /// Canonical AppImage provenance.
        #[arg(long, value_name = "JSON")]
        provenance: PathBuf,
        /// Canonical signed update manifest.
        #[arg(long, value_name = "JSON")]
        update_manifest: PathBuf,
        /// Canonical engineering release-readiness assessment.
        #[arg(long, value_name = "JSON")]
        release_readiness: PathBuf,
        /// Canonical first AppDir manifest.
        #[arg(long, value_name = "JSON")]
        appdir_manifest: PathBuf,
        /// Exact Cargo.lock from the assessed source tree.
        #[arg(long, value_name = "LOCKFILE")]
        cargo_lock: PathBuf,
        /// Expected exact 40-character source commit.
        #[arg(long, value_name = "HEX")]
        source_commit: String,
        /// Expected exact 40-character Git source tree.
        #[arg(long, value_name = "HEX")]
        source_tree: String,
    },
    /// Assess one exact candidate against every independent release gate.
    ReleaseReadiness {
        /// Authenticated stage generation to re-authenticate completely.
        #[arg(long, value_name = "DIRECTORY")]
        stage: PathBuf,
        /// Exact native-build manifest consumed by runtime assembly.
        #[arg(long, value_name = "JSON")]
        native_manifest: PathBuf,
        /// Exact runtime manifest consumed by AppDir construction.
        #[arg(long, value_name = "JSON")]
        runtime_manifest: PathBuf,
        /// Exact AppDir manifest consumed by AppImage construction.
        #[arg(long, value_name = "JSON")]
        appdir_manifest: PathBuf,
        /// Exact final AppImage provenance.
        #[arg(long, value_name = "JSON")]
        appimage_provenance: PathBuf,
        /// Exact final AppImage bytes.
        #[arg(long, value_name = "APPIMAGE")]
        artifact: PathBuf,
        /// Exact Cargo.lock for the assessed source candidate.
        #[arg(long, value_name = "LOCKFILE")]
        cargo_lock: PathBuf,
    },
}

impl PackagingCommand {
    /// Returns the stable command-line spelling.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Inspect { .. } => "inspect",
            Self::CheckUpstream { .. } => "check-upstream",
            Self::AcquireArtifact { .. } => "acquire-artifact",
            Self::InspectArtifact { .. } => "inspect-artifact",
            Self::Stage { .. } => "stage",
            Self::Extract { .. } => "extract",
            Self::BuildNative { .. } => "build-native",
            Self::AssembleRuntime { .. } => "assemble-runtime",
            Self::BuildAppdir { .. } => "build-appdir",
            Self::PackAppimage { .. } => "pack-appimage",
            Self::GenerateUpdateKey { .. } => "generate-update-key",
            Self::SignUpdate { .. } => "sign-update",
            Self::PrepareRelease { .. } => "prepare-release",
            Self::VerifyRelease { .. } => "verify-release",
            Self::ReleaseReadiness { .. } => "release-readiness",
        }
    }
}
