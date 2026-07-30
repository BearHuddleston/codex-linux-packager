#![forbid(unsafe_code)]

use codex_linux_packager::appimage::appimage_contract;

#[test]
fn embedded_appimage_tools_are_stable_tagged_and_exactly_pinned() {
    let contract = appimage_contract().expect("embedded AppImage contract");

    assert_eq!(contract.schema, 1);
    assert_eq!(contract.target, "linux-x86_64");
    assert_eq!(contract.appimagetool.release, "1.9.1");
    assert_ne!(contract.appimagetool.release, "continuous");
    assert_eq!(
        contract.appimagetool.sha256,
        "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
    );
    assert_eq!(contract.type2_runtime.release, "20251108");
    assert_ne!(contract.type2_runtime.release, "continuous");
    assert_eq!(
        contract.type2_runtime.sha256,
        "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"
    );
    assert_eq!(contract.type2_runtime.digest_mutation_offset, 932_096);
    assert_eq!(contract.type2_runtime.digest_mutation_bytes, 16);
    assert_eq!(
        contract.older_glibc_baseline.base_image,
        "docker.io/library/node@sha256:20a424ecd1d2064a44e12fe287bf3dae443aab31dc5e0c0cb6c74bef9c78911c"
    );
    assert_eq!(contract.older_glibc_baseline.glibc_version, "2.36");
    assert_eq!(contract.older_glibc_baseline.package_count, 494);
}
