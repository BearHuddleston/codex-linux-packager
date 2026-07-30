#![forbid(unsafe_code)]

use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use codex_linux_packager::manifest::{ErrorDocument, to_json_line};
use codex_linux_packager::updater::run_packaged_update;

#[derive(Debug, Parser)]
#[command(
    name = "codex-linux-updater",
    version,
    about = "Pinned-key background updater for codex-linux-packager AppImages",
    arg_required_else_help = true
)]
struct Cli {
    /// Absolute path named by the AppImage runtime's APPIMAGE variable.
    #[arg(long, value_name = "APPIMAGE")]
    current_appimage: PathBuf,
    /// Absolute schema-1 update config embedded in the mounted AppDir.
    #[arg(long, value_name = "JSON")]
    config: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run_packaged_update(&cli.current_appimage, &cli.config) {
        Ok(report) => match write_json(io::stdout().lock(), &report) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let _ = writeln!(io::stderr().lock(), "write updater result: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            let document = ErrorDocument::new("appimage_update_failed", error.to_string());
            let _ = write_json(io::stderr().lock(), &document);
            ExitCode::FAILURE
        }
    }
}

fn write_json(
    mut destination: impl io::Write,
    document: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = to_json_line(document)?;
    destination.write_all(encoded.as_bytes())?;
    Ok(())
}
