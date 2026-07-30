#![forbid(unsafe_code)]

use codex_linux_packager::manifest::to_json_line;
use codex_linux_packager::update::embedded_update_contract;
use codex_linux_packager::updater::{
    UpdateRuntimeConfig, create_runtime_update_config, validate_runtime_update_config,
};

#[test]
fn packaged_update_config_is_versioned_deterministic_and_bound_to_the_compiled_key() {
    let contract = embedded_update_contract().expect("embedded update contract");
    let config =
        create_runtime_update_config("26.721.81911", "5973").expect("runtime update config");
    let encoded = to_json_line(&config).expect("canonical config");
    let decoded: UpdateRuntimeConfig =
        serde_json::from_slice(encoded.as_bytes()).expect("strict config JSON");

    validate_runtime_update_config(&decoded, &contract).expect("validate runtime config");
    assert_eq!(decoded, config);
    assert_eq!(config.manifest_url, contract.manifest_url);
    assert_eq!(config.public_key_sha256, contract.public_key_sha256);
    assert_eq!(
        config.behavior,
        "background_full_download_activate_for_next_launch_keep_versioned_rollback"
    );
    assert!(encoded.ends_with('\n'));
}

#[test]
fn embedded_release_key_matches_the_reviewed_public_fingerprint() {
    let contract = embedded_update_contract().expect("embedded update contract");

    assert_eq!(
        contract.public_key_sha256,
        "fd6ea6bd85ff0f85fc7f45190c505317491a59fbfd872686e2debbe41e868314"
    );
    assert_eq!(
        contract.manifest_url,
        "https://github.com/BearHuddleston/codex-linux-packager/releases/latest/download/codex-linux-x86_64-update.json"
    );
    assert_eq!(contract.target, "linux-x86_64");
}
