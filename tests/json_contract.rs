#![forbid(unsafe_code)]

use codex_linux_packager::manifest::{
    DocumentHeader, PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line,
};

#[test]
fn current_header_has_exact_deterministic_json_identity() {
    let header = DocumentHeader::current();

    assert_eq!(header.schema(), SCHEMA_VERSION);
    assert_eq!(header.producer(), PRODUCER_IDENTIFIER);
    assert_eq!(
        to_json_line(&header).expect("current header should serialize"),
        concat!(
            "{\"schema\":1,\"producer\":",
            "\"io.github.bearhuddleston.codex-linux-packager.rust\"}\n"
        )
    );
}

#[test]
fn document_header_rejects_every_noncurrent_schema() {
    for schema in [0, 2, 3, u32::MAX] {
        let encoded = format!("{{\"schema\":{schema},\"producer\":\"{PRODUCER_IDENTIFIER}\"}}");
        let error = serde_json::from_str::<DocumentHeader>(&encoded)
            .expect_err("old and unknown schemas must be rejected");

        assert!(
            error.to_string().contains("unsupported document schema"),
            "unexpected error for schema {schema}: {error}"
        );
    }
}

#[test]
fn document_header_rejects_a_foreign_producer() {
    let encoded = r#"{"schema":1,"producer":"python-schema-3-compat"}"#;
    let error = serde_json::from_str::<DocumentHeader>(encoded)
        .expect_err("documents from another producer must be rejected");

    assert!(
        error.to_string().contains("unexpected document producer"),
        "unexpected error: {error}"
    );
}

#[test]
fn document_header_rejects_unknown_fields() {
    let encoded = format!(
        concat!(
            "{{\"schema\":1,\"producer\":\"{}\",",
            "\"legacy_schema\":3}}"
        ),
        PRODUCER_IDENTIFIER
    );

    serde_json::from_str::<DocumentHeader>(&encoded)
        .expect_err("unknown fields must not be silently consumed");
}
