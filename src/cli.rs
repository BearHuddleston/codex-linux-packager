//! Command-line contract shared by the binary and integration tests.

use clap::{Parser, Subcommand};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum PackagingCommand {
    /// Inspect release metadata from the Codex Sparkle feed.
    Inspect,
    /// Authenticate and inspect a downloaded desktop artifact.
    InspectArtifact,
    /// Authenticate and stage the narrow permitted source set.
    Stage,
    /// Extract authenticated staged inputs for a later phase.
    Extract,
    /// Rebuild required native modules for the target Electron ABI.
    BuildNative,
    /// Assemble the pinned Linux x86_64 Electron runtime.
    AssembleRuntime,
    /// Construct a deterministic AppDir.
    BuildAppdir,
    /// Construct and verify a deterministic AppImage.
    PackAppimage,
}

impl PackagingCommand {
    /// Returns the stable command-line spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::InspectArtifact => "inspect-artifact",
            Self::Stage => "stage",
            Self::Extract => "extract",
            Self::BuildNative => "build-native",
            Self::AssembleRuntime => "assemble-runtime",
            Self::BuildAppdir => "build-appdir",
            Self::PackAppimage => "pack-appimage",
        }
    }
}
