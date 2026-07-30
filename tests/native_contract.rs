#![forbid(unsafe_code)]

use codex_linux_packager::native::native_contract;

#[test]
fn embedded_native_contract_pins_the_exact_linux_x86_64_electron_abi() {
    let contract = native_contract().expect("embedded native contract must validate");

    assert_eq!(contract.schema, 1);
    assert_eq!(contract.target.os, "linux");
    assert_eq!(contract.target.architecture, "x86_64");
    assert_eq!(contract.electron.version, "42.3.0");
    assert_eq!(contract.electron.node_version, "24.15.0");
    assert_eq!(contract.electron.module_abi, 146);
    assert_eq!(
        contract.build_image.reference,
        "docker.io/library/node@sha256:20a424ecd1d2064a44e12fe287bf3dae443aab31dc5e0c0cb6c74bef9c78911c"
    );
    assert_eq!(contract.build_image.glibc_version, "2.36");
    assert_eq!(contract.build_image.maximum_output_glibc_version, "2.36");
    assert_eq!(
        contract
            .packages
            .iter()
            .map(|package| (package.name.as_str(), package.version.as_str()))
            .collect::<Vec<_>>(),
        [("better-sqlite3", "12.9.0"), ("node-pty", "1.1.0")]
    );
    assert_eq!(contract.source_patches.len(), 1);
    let patch = &contract.source_patches[0];
    assert_eq!(patch.package, "better-sqlite3");
    assert_eq!(patch.package_version, "12.9.0");
    assert_eq!(
        patch.upstream_commit,
        "5bb63a2f4c5aa34de2c292b983d2b6c4fcfc6f94"
    );
    assert_eq!(
        patch.upstream_repository,
        "https://github.com/WiseLibs/better-sqlite3"
    );
    assert_eq!(
        patch.patch_sha256,
        "f7019e9a83e8a39f323db743b8bd179384e0d7aa741257e2141bbd5af0a4a421"
    );
    assert_eq!(patch.files.len(), 3);
}
