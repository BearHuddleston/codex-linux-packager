#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn help_exposes_every_planned_command_concept() {
    let output = Command::new(env!("CARGO_BIN_EXE_codex-linux-packager"))
        .arg("--help")
        .output()
        .expect("CLI should start");

    assert!(
        output.status.success(),
        "help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");
    for command in [
        "inspect",
        "inspect-artifact",
        "stage",
        "extract",
        "build-native",
        "assemble-runtime",
        "build-appdir",
        "pack-appimage",
    ] {
        assert!(
            stdout
                .lines()
                .any(|line| line.split_whitespace().next() == Some(command)),
            "help did not include {command:?}:\n{stdout}"
        );
    }
}

#[test]
fn unimplemented_phase_is_an_explicit_versioned_json_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_codex-linux-packager"))
        .arg("inspect")
        .output()
        .expect("CLI should start");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "failures must not write to stdout"
    );
    assert_eq!(
        String::from_utf8(output.stderr).expect("error document should be UTF-8"),
        concat!(
            "{\"schema\":1,",
            "\"producer\":\"io.github.bearhuddleston.codex-linux-packager.rust\",",
            "\"ok\":false,",
            "\"error\":{\"code\":\"phase_not_implemented\",",
            "\"message\":\"command `inspect` is not implemented in phase 0\"}}\n"
        )
    );
}
