#![forbid(unsafe_code)]

use codex_linux_packager::runtime::runtime_contract;

#[test]
fn embedded_runtime_contract_matches_authenticated_desktop_resources() {
    let contract = runtime_contract().expect("embedded runtime contract must validate");

    assert_eq!(contract.schema, 1);
    assert_eq!(contract.target.os, "linux");
    assert_eq!(contract.target.architecture, "x86_64");
    assert_eq!(contract.application.version, "26.727.40816");
    assert_eq!(contract.application.build, "6067");
    assert_eq!(contract.codex.version, "0.146.0-alpha.9.2");
    assert_eq!(
        contract.codex.revision,
        "86cc9f2177cad015befd595286d8767a650f7d13"
    );
    assert_eq!(
        contract.codex.package_archive_sha256,
        "a84c7cd5a8bc14cb63e4d6688d4792c8b2254ba6cc06985e63c1538271ffa857"
    );
    assert_eq!(contract.codex.package_archive_bytes, 133_490_612);
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
