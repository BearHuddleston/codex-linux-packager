#![forbid(unsafe_code)]

use codex_linux_packager::runtime::{runtime_contract, validate_runtime_contract};

#[test]
fn embedded_runtime_contract_matches_authenticated_desktop_resources() {
    let contract = runtime_contract().expect("embedded runtime contract must validate");

    assert_eq!(contract.schema, 1);
    assert_eq!(contract.target.os, "linux");
    assert_eq!(contract.target.architecture, "x86_64");
    assert_eq!(
        contract.codex.release_tag,
        format!("rust-v{}", contract.codex.version)
    );
    assert_eq!(contract.codex.components.len(), 6);
    let codex = contract
        .authenticated_source_resources
        .iter()
        .find(|resource| resource.name == "codex")
        .expect("Codex must be correlated by its authenticated marker");
    assert_eq!(
        codex.identity_marker.as_deref(),
        Some(contract.codex.version.as_str())
    );
    let ripgrep = contract
        .authenticated_source_resources
        .iter()
        .find(|resource| resource.name == "rg")
        .expect("ripgrep must be correlated by its authenticated marker");
    assert_eq!(
        ripgrep.identity_marker,
        Some(format!(
            "{}{}",
            contract.ripgrep.version,
            &contract.ripgrep.revision[..10]
        ))
    );
    let code_mode_host = contract
        .authenticated_source_resources
        .iter()
        .find(|resource| resource.name == "codex-code-mode-host")
        .expect("code-mode host must be correlated by its authenticated digest");
    assert_eq!(
        code_mode_host.identity_marker, None,
        "the source code-mode host does not carry a truthful version string"
    );
}

#[test]
fn runtime_contract_validation_accepts_a_new_authenticated_application_identity() {
    let mut contract = runtime_contract().expect("embedded runtime contract must validate");
    contract.application.version = "26.801.10001".to_owned();
    contract.application.build = "7001".to_owned();
    contract.application.app_asar_sha256 = "a".repeat(64);
    contract.codex.version = "0.147.0-alpha.1".to_owned();
    contract.codex.release_tag = "rust-v0.147.0-alpha.1".to_owned();
    contract
        .authenticated_source_resources
        .iter_mut()
        .find(|resource| resource.name == "codex")
        .expect("Codex source resource")
        .identity_marker = Some("0.147.0-alpha.1".to_owned());

    validate_runtime_contract(&contract)
        .expect("validation must be structural and digest-bound, not tied to one app release");
}
