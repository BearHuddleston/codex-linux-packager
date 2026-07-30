#![forbid(unsafe_code)]

use codex_linux_packager::feed::{
    FeedSource, OFFICIAL_FEED_URL, inspect_feed_bytes, inspect_feed_fixture,
};

#[test]
fn parses_a_strict_synthetic_x86_64_release() {
    let signature =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let xml = synthetic_feed();

    let inspection = inspect_feed_bytes(
        xml.as_bytes(),
        FeedSource::OfficialHttps {
            url: OFFICIAL_FEED_URL.to_owned(),
        },
    )
    .expect("synthetic feed should parse");

    assert_eq!(inspection.schema, 1);
    assert_eq!(inspection.kind, "feed_inspection");
    assert_eq!(inspection.channel_title, "Codex");
    assert_eq!(inspection.releases.len(), 1);
    let release = &inspection.releases[0];
    assert_eq!(release.version, "26.721.81911");
    assert_eq!(release.build, "5973");
    assert_eq!(release.hardware_requirements, "x86_64");
    assert_eq!(release.artifact.length, 545_069_607);
    assert_eq!(release.artifact.ed25519_signature, signature);
}

#[test]
fn rejects_truncated_xml() {
    let xml = synthetic_feed();
    let truncated = &xml.as_bytes()[..xml.len() - "</rss>".len()];

    inspect_feed_bytes(
        truncated,
        FeedSource::OfficialHttps {
            url: OFFICIAL_FEED_URL.to_owned(),
        },
    )
    .expect_err("truncated XML must be rejected");
}

#[test]
fn rejects_an_artifact_outside_the_exact_https_origin() {
    let xml = synthetic_feed().replace(
        "https://persistent.oaistatic.com/codex-app-prod/",
        "http://attacker.invalid/",
    );

    inspect_feed_bytes(
        xml.as_bytes(),
        FeedSource::OfficialHttps {
            url: OFFICIAL_FEED_URL.to_owned(),
        },
    )
    .expect_err("unsafe artifact URL must be rejected");
}

#[test]
fn derives_x86_64_from_the_fixed_feed_when_sparkle_omits_it() {
    let xml = synthetic_feed().replace(
        "      <sparkle:hardwareRequirements>x86_64</sparkle:hardwareRequirements>\n",
        "",
    );

    let inspection = inspect_feed_bytes(
        xml.as_bytes(),
        FeedSource::OfficialHttps {
            url: OFFICIAL_FEED_URL.to_owned(),
        },
    )
    .expect("the fixed x86_64 feed establishes architecture");

    assert_eq!(inspection.releases[0].hardware_requirements, "x86_64");
    assert_eq!(
        inspection.releases[0].architecture_source,
        "fixed_x86_64_feed_endpoint"
    );
}

#[test]
fn rejects_dtd_entity_and_nul_envelopes_before_parsing() {
    for bytes in [
        b"<?xml version=\"1.0\"?><!DOCTYPE rss><rss/>".as_slice(),
        b"<?xml version=\"1.0\"?><!ENTITY x \"x\"><rss/>".as_slice(),
        b"<?xml version=\"1.0\"?><rss>\0</rss>".as_slice(),
    ] {
        inspect_feed_bytes(
            bytes,
            FeedSource::OfficialHttps {
                url: OFFICIAL_FEED_URL.to_owned(),
            },
        )
        .expect_err("hostile XML envelope must be rejected");
    }
}

#[test]
fn reads_a_bounded_regular_local_fixture() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let path = temporary.path().join("feed.xml");
    std::fs::write(&path, synthetic_feed()).expect("write synthetic fixture");

    let inspection = inspect_feed_fixture(&path).expect("regular fixture should be inspected");

    assert_eq!(
        inspection.source,
        FeedSource::LocalFixture {
            path: path.display().to_string(),
        }
    );
    assert_eq!(inspection.releases.len(), 1);
}

#[cfg(unix)]
#[test]
fn refuses_a_symlinked_local_fixture() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("create temporary directory");
    let target = temporary.path().join("target.xml");
    let link = temporary.path().join("feed.xml");
    std::fs::write(&target, synthetic_feed()).expect("write target");
    symlink(&target, &link).expect("create symlink");

    inspect_feed_fixture(&link).expect_err("fixture symlinks must be rejected");
}

#[test]
fn refuses_an_oversized_local_fixture() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let path = temporary.path().join("feed.xml");
    std::fs::write(&path, vec![b'x'; 256 * 1024 + 1]).expect("write oversized fixture");

    inspect_feed_fixture(&path).expect_err("oversized fixture must be rejected");
}

fn synthetic_feed() -> String {
    let signature =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">
  <channel>
    <title>Codex</title>
    <item>
      <title>26.721.81911</title>
      <pubDate>Wed, 29 Jul 2026 07:00:18 +0000</pubDate>
      <sparkle:version>5973</sparkle:version>
      <sparkle:shortVersionString>26.721.81911</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>12.0</sparkle:minimumSystemVersion>
      <sparkle:hardwareRequirements>x86_64</sparkle:hardwareRequirements>
      <enclosure
        url="https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-x64-26.721.81911.zip"
        length="545069607"
        type="application/octet-stream"
        sparkle:edSignature="{signature}" />
    </item>
  </channel>
</rss>"#
    )
}
