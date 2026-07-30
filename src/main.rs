#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use codex_linux_packager::appdir::{AppDirRequest, build_appdir};
use codex_linux_packager::appimage::{AppImageRequest, LaunchBackend, pack_appimage};
use codex_linux_packager::archive::{ArtifactContract, ArtifactTrust, inspect_artifact_file};
use codex_linux_packager::cli::{ArtifactArguments, Cli, LaunchBackendArgument, PackagingCommand};
use codex_linux_packager::download::download_official_feed;
use codex_linux_packager::extract::extract_stage;
use codex_linux_packager::feed::{FeedSource, inspect_feed_bytes, inspect_feed_fixture};
use codex_linux_packager::manifest::{ErrorDocument, to_json_line};
use codex_linux_packager::native::{NativeBuildRequest, build_native};
use codex_linux_packager::release::{ReleaseAssessmentRequest, assess_release_readiness};
use codex_linux_packager::runtime::{RuntimeAssemblyRequest, assemble_runtime};
use codex_linux_packager::staging::stage_artifact_file;

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "internal CLI error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    match &cli.command {
        PackagingCommand::Inspect { fixture } => {
            let inspection = if let Some(path) = fixture {
                inspect_feed_fixture(path).map_err(|error| {
                    ErrorDocument::new("feed_inspection_failed", error.to_string())
                })
            } else {
                download_official_feed()
                    .map_err(|error| ErrorDocument::new("feed_download_failed", error.to_string()))
                    .and_then(|downloaded| {
                        inspect_feed_bytes(
                            &downloaded.bytes,
                            FeedSource::OfficialHttps {
                                url: downloaded.final_url,
                            },
                        )
                        .map_err(|error| {
                            ErrorDocument::new("feed_inspection_failed", error.to_string())
                        })
                    })
            };

            match inspection {
                Ok(document) => {
                    write_document(io::stdout().lock(), &document)
                        .context("write feed inspection")?;
                    Ok(ExitCode::SUCCESS)
                }
                Err(document) => {
                    write_document(io::stderr().lock(), &document).context("write feed error")?;
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        PackagingCommand::InspectArtifact { artifact } => {
            let result = artifact_contract(artifact)
                .and_then(|(contract, trust)| {
                    inspect_artifact_file(&artifact.artifact, &contract, &trust)
                        .map_err(anyhow::Error::from)
                })
                .map_err(|error| {
                    ErrorDocument::new("artifact_inspection_failed", error.to_string())
                });
            emit_result(result, "artifact inspection")
        }
        PackagingCommand::Stage { artifact, output } => {
            let result = artifact_contract(artifact)
                .and_then(|(contract, trust)| {
                    stage_artifact_file(&artifact.artifact, output, &contract, &trust)
                        .map_err(anyhow::Error::from)
                })
                .map_err(|error| ErrorDocument::new("artifact_staging_failed", error.to_string()));
            emit_result(result, "artifact stage")
        }
        PackagingCommand::Extract { stage, output } => {
            let result = extract_stage(stage, output)
                .map_err(|error| ErrorDocument::new("asar_extraction_failed", error.to_string()));
            emit_result(result, "ASAR extraction")
        }
        PackagingCommand::BuildNative {
            stage,
            electron_zip,
            electron_headers,
            npm_cache,
            work,
            output,
            allow_network,
            node,
            npm,
            oci_runtime,
            oci_runtime_sha256,
            sudo_program,
            sudo_sha256,
        } => {
            let request = NativeBuildRequest {
                stage: stage.clone(),
                electron_zip: electron_zip.clone(),
                electron_headers: electron_headers.clone(),
                npm_cache: npm_cache.clone(),
                work_directory: work.clone(),
                output: output.clone(),
                allow_network: *allow_network,
                node_program: node.clone(),
                npm_program: npm.clone(),
                oci_runtime: oci_runtime.clone(),
                oci_runtime_sha256: oci_runtime_sha256.clone(),
                sudo_program: sudo_program.clone(),
                sudo_sha256: sudo_sha256.clone(),
            };
            let result = build_native(&request)
                .map_err(|error| ErrorDocument::new("native_build_failed", error.to_string()));
            emit_result(result, "native build")
        }
        PackagingCommand::AssembleRuntime {
            stage,
            native,
            native_manifest_sha256,
            electron_zip,
            codex_package,
            output,
        } => {
            let request = RuntimeAssemblyRequest {
                stage: stage.clone(),
                native: native.clone(),
                native_manifest_sha256: native_manifest_sha256.clone(),
                electron_zip: electron_zip.clone(),
                codex_package: codex_package.clone(),
                output: output.clone(),
            };
            let result = assemble_runtime(&request)
                .map_err(|error| ErrorDocument::new("runtime_assembly_failed", error.to_string()));
            emit_result(result, "runtime assembly")
        }
        PackagingCommand::BuildAppdir {
            runtime,
            runtime_manifest_sha256,
            source_date_epoch,
            output,
        } => {
            let request = AppDirRequest {
                runtime: runtime.clone(),
                runtime_manifest_sha256: runtime_manifest_sha256.clone(),
                output: output.clone(),
                source_date_epoch: *source_date_epoch,
            };
            let result = build_appdir(&request)
                .map_err(|error| ErrorDocument::new("appdir_build_failed", error.to_string()));
            emit_result(result, "AppDir build")
        }
        PackagingCommand::PackAppimage {
            appdir,
            appdir_manifest_sha256,
            reproduction_appdir,
            reproduction_appdir_manifest_sha256,
            appimagetool,
            type2_runtime,
            bubblewrap,
            bubblewrap_sha256,
            readelf,
            readelf_sha256,
            oci_runtime,
            oci_runtime_sha256,
            sudo_program,
            sudo_sha256,
            older_glibc_image_id,
            launch_backend,
            output,
        } => {
            let request = AppImageRequest {
                appdir: appdir.clone(),
                appdir_manifest_sha256: appdir_manifest_sha256.clone(),
                reproduction_appdir: reproduction_appdir.clone(),
                reproduction_appdir_manifest_sha256: reproduction_appdir_manifest_sha256.clone(),
                appimagetool: appimagetool.clone(),
                type2_runtime: type2_runtime.clone(),
                bubblewrap: bubblewrap.clone(),
                bubblewrap_sha256: bubblewrap_sha256.clone(),
                readelf: readelf.clone(),
                readelf_sha256: readelf_sha256.clone(),
                oci_runtime: oci_runtime.clone(),
                oci_runtime_sha256: oci_runtime_sha256.clone(),
                sudo_program: sudo_program.clone(),
                sudo_sha256: sudo_sha256.clone(),
                older_glibc_image_id: older_glibc_image_id.clone(),
                launch_backends: launch_backend
                    .iter()
                    .map(|backend| match backend {
                        LaunchBackendArgument::Wayland => LaunchBackend::Wayland,
                        LaunchBackendArgument::X11 => LaunchBackend::X11,
                    })
                    .collect(),
                output: output.clone(),
            };
            let result = pack_appimage(&request)
                .map_err(|error| ErrorDocument::new("appimage_build_failed", error.to_string()));
            emit_result(result, "AppImage build")
        }
        PackagingCommand::ReleaseReadiness {
            stage,
            native_manifest,
            runtime_manifest,
            appdir_manifest,
            appimage_provenance,
            artifact,
            cargo_lock,
        } => {
            let request = ReleaseAssessmentRequest {
                stage: stage.clone(),
                native_manifest: native_manifest.clone(),
                runtime_manifest: runtime_manifest.clone(),
                appdir_manifest: appdir_manifest.clone(),
                appimage_provenance: appimage_provenance.clone(),
                artifact: artifact.clone(),
                cargo_lock: cargo_lock.clone(),
            };
            let result = assess_release_readiness(&request).map_err(|error| {
                ErrorDocument::new("release_readiness_assessment_failed", error.to_string())
            });
            emit_result(result, "release readiness assessment")
        }
    }
}

fn artifact_contract(
    arguments: &ArtifactArguments,
) -> anyhow::Result<(ArtifactContract, ArtifactTrust)> {
    let trust = ArtifactTrust::pinned_production().context("load pinned production trust root")?;
    Ok((
        ArtifactContract {
            expected_length: arguments.length,
            signature_base64: arguments.signature.clone(),
            version: arguments.version.clone(),
            build: arguments.build.clone(),
        },
        trust,
    ))
}

fn emit_result<T: serde::Serialize>(
    result: Result<T, ErrorDocument>,
    context: &'static str,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(document) => {
            write_document(io::stdout().lock(), &document)
                .with_context(|| format!("write {context}"))?;
            Ok(ExitCode::SUCCESS)
        }
        Err(document) => {
            write_document(io::stderr().lock(), &document)
                .with_context(|| format!("write {context} error"))?;
            Ok(ExitCode::FAILURE)
        }
    }
}

fn write_document(
    mut destination: impl Write,
    document: &impl serde::Serialize,
) -> anyhow::Result<()> {
    let encoded = to_json_line(document).context("encode JSON document")?;
    destination
        .write_all(encoded.as_bytes())
        .context("write JSON document")
}
