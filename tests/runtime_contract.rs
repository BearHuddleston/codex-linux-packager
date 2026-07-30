#![forbid(unsafe_code)]

use codex_linux_packager::runtime::runtime_contract;

#[test]
fn embedded_runtime_contract_matches_authenticated_desktop_resources() {
    let contract = runtime_contract().expect("embedded runtime contract must validate");

    assert_eq!(contract.schema, 1);
    assert_eq!(contract.target.os, "linux");
    assert_eq!(contract.target.architecture, "x86_64");
    assert_eq!(contract.application.version, "26.721.81911");
    assert_eq!(contract.application.build, "5973");
    assert_eq!(contract.codex.version, "0.146.0-alpha.3.1");
    assert_eq!(
        contract.codex.revision,
        "ff75c5b939c477c49eb1bd5248da6dab71b109d1"
    );
    assert_eq!(contract.ripgrep.version, "15.2.0");
    assert_eq!(
        contract.ripgrep.revision,
        "e89fff89ac9af12e8d4ce9d5fd07beb408ca730f"
    );
    assert_eq!(contract.codex.components.len(), 6);
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
