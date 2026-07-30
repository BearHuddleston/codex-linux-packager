# Sparkle trust bootstrap

This document records the independent trust bootstrap for the production
Sparkle Ed25519 public key. A key found only inside the archive whose Sparkle
signature is being checked would be self-authenticating and is not accepted.

## Pinned identity

- Raw public key, standard Base64:
  `mNfr1v9t63BfgDtlw4C8lRvSY6uMggIXABDOCi3tS6k=`
- Decoded length: 32 bytes
- SHA-256 of decoded bytes:
  `9ffe67dd945eba7930671c7c7f4dbfc84b7ddcebe7618f82f227f1f70ef20058`
- Expected bundle identifier: `com.openai.codex`
- Expected Apple Developer Team ID: `2DC432GLL2`

Rotation of this key requires a reviewed source change and a new independent
bootstrap. A future bundle cannot authorize its own replacement key.

## Independent authentication record

The bootstrap was reproduced on 2026-07-30 from the x86_64 release
`26.721.81911` (build `5973`).

OpenAI's public `openai/codex` repository at commit
`3d805abdf09093bfa806f359a5adc6514766c420` independently identifies the
OpenAI-controlled distribution origin and the x86_64 desktop download in
`codex-rs/cli/src/desktop_app/mac.rs`. The fixed x86_64 Sparkle feed on that
origin identified this exact archive:

- URL:
  `https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-x64-26.721.81911.zip`
- Length: `536039698`
- Archive SHA-256:
  `4e237b5b0b092225522b1380ca93a52242bcef1fed9ce33d2bf304e2993b844c`

Only the canonical bundle `Info.plist` and its declared main executable were
extracted for the bootstrap:

- `ChatGPT.app/Contents/Info.plist` SHA-256:
  `63dc4aca84e0e86287a32373cbf7c946d9d64d329bd3054176a40eb305b29c4a`
- `ChatGPT.app/Contents/MacOS/ChatGPT` SHA-256:
  `ae0d7d753d4942211c658341e5999ae28cb58873ff1c0850ca9b960b3b79ce45`

The main executable's signed CodeDirectory has identifier
`com.openai.codex`, Team ID `2DC432GLL2`, SHA-256
`2e64fd99c52f721823424e8dfaca8b9eaab29ad10a8732fba78358045208e2f3`,
and an Info slot equal to the complete `Info.plist` SHA-256 above. Its CMS
`SignerInfo` selects this leaf certificate:

- Subject:
  `Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)`
- Serial: `315B87E03811A48BD81789E1F0C20E4C`
- Leaf SHA-256 fingerprint:
  `04f747c40a6e9b8739fe59da61cc41d9519544659a1009c5f5629577ed57edd5`
- Extended key usage: critical Code Signing

OpenSSL verified the CMS signature over the exact CodeDirectory and emitted
that actual signer certificate. The signer then verified, with Apple's
proprietary critical extensions explicitly tolerated, through the independently
downloaded official Developer ID G2 intermediate to Apple's official root:

- Apple Root CA DER SHA-256:
  `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024`
- Developer ID G2 CA DER SHA-256:
  `f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a`

Both certificates came from Apple's PKI page at
`https://www.apple.com/certificateauthority/`. The two-step OpenSSL check is
intentional: ordinary OpenSSL rejects Apple's proprietary critical Developer ID
extension. `cms -verify -noverify` first binds and verifies the actual
`SignerInfo`; `openssl verify -ignore_critical` then validates that exact signer
through the separately obtained Apple chain. Merely finding a pinned certificate
somewhere in the CMS collection is not sufficient.

The authenticated plist declared the pinned `SUPublicEDKey` above. Its other
critical values were `CFBundleIdentifier=com.openai.codex`,
`CFBundleExecutable=ChatGPT`, `CFBundleShortVersionString=26.721.81911`, and
`CFBundleVersion=5973`.

## Sparkle signature semantics

Sparkle's official `2.x` source at commit
`4a84bf21086398d05a39d02cbe87a54cf66dbaba` establishes the interoperability
contract:

- `common_cli/Signing.swift` reads the complete file and passes those exact
  bytes to `ed25519_sign`;
- `sign_update/main.swift` passes the complete file bytes, decoded 64-byte
  signature, and decoded 32-byte public key to `ed25519_verify`;
- `Autoupdate/SUSignatureVerifier.m` uses the same verifier on the downloaded
  data.

Therefore `sparkle:edSignature` is standard Ed25519 over the exact complete
archive bytes, not over a precomputed digest or a framed message. This project
uses strict RFC 8032 verification and rejects non-canonical Base64.

## Reproduction outline

Acquired files belong under ignored `work/`; never add them to Git.

1. Fetch the fixed feed with redirects disabled and record the exact enclosure.
2. Fetch that enclosure with exact length enforcement and compute SHA-256.
3. Extract only the canonical plist and declared executable.
4. Use `rcodesign extract cms-raw` and `code-directory-raw` to obtain the CMS
   and signed CodeDirectory.
5. Run `openssl cms -verify -binary -inform DER ... -noverify -signer ...` over
   the exact CodeDirectory.
6. Verify the emitted signer using the official Apple root and Developer ID G2
   intermediate, and bind the leaf subject, serial, fingerprint, Team ID, and
   Code Signing EKU.
7. Require the CodeDirectory identifier and Team ID above and require its Info
   slot digest to equal the exact plist digest.
8. Decode `SUPublicEDKey`, require 32 canonical bytes, and compute its SHA-256.
9. Verify the feed signature on the complete archive with that key.

This bootstrap authenticates one public trust root. It does not grant payload
redistribution or trademark rights and does not clear any release gate.
