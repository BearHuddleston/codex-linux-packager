#![forbid(unsafe_code)]

use codex_linux_packager::asar::inspect_asar_bytes;
use sha2::{Digest, Sha256};

#[test]
fn validates_a_canonical_synthetic_asar_and_every_integrity_digest() {
    let contents = b"let answer = 42;\n";
    let digest = hex_lower(&Sha256::digest(contents));
    let header = format!(
        concat!(
            "{{\"files\":{{\"main.js\":{{",
            "\"size\":{},\"offset\":\"0\",",
            "\"integrity\":{{\"algorithm\":\"SHA256\",",
            "\"hash\":\"{}\",\"blockSize\":4194304,",
            "\"blocks\":[\"{}\"]}}",
            "}}}}}}"
        ),
        contents.len(),
        digest,
        digest
    );
    let asar = encode_asar(&header, contents);

    let inspection = inspect_asar_bytes(&asar).expect("canonical ASAR should inspect");

    assert_eq!(inspection.schema, 1);
    assert_eq!(inspection.kind, "asar_inspection");
    assert_eq!(inspection.packed_file_count, 1);
    assert_eq!(inspection.unpacked_file_count, 0);
    assert_eq!(inspection.packed_data_bytes, contents.len() as u64);
}

fn encode_asar(header_json: &str, data: &[u8]) -> Vec<u8> {
    let json = header_json.as_bytes();
    let unpadded_payload = 4_usize + json.len() + 1;
    let string_payload = (unpadded_payload + 3) & !3;
    let header_pickle = 4_usize + string_payload;
    let mut output = Vec::with_capacity(8 + header_pickle + data.len());
    output.extend_from_slice(&4_u32.to_le_bytes());
    output.extend_from_slice(
        &u32::try_from(header_pickle)
            .expect("header size fits")
            .to_le_bytes(),
    );
    output.extend_from_slice(
        &u32::try_from(string_payload)
            .expect("payload size fits")
            .to_le_bytes(),
    );
    output.extend_from_slice(
        &u32::try_from(json.len())
            .expect("JSON size fits")
            .to_le_bytes(),
    );
    output.extend_from_slice(json);
    output.push(0);
    output.resize(8 + header_pickle, 0);
    output.extend_from_slice(data);
    output
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
