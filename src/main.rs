#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use codex_linux_packager::cli::Cli;
use codex_linux_packager::manifest::{ErrorDocument, to_json_line};

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
    let document = ErrorDocument::phase_not_implemented(cli.command.as_str());
    let encoded = to_json_line(&document).context("encode error document")?;
    io::stderr()
        .lock()
        .write_all(encoded.as_bytes())
        .context("write error document")?;
    Ok(ExitCode::FAILURE)
}
