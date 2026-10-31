# Third-party notices for Desktop 1.4.0

The original desktop application files retain their existing notices. The native Aether engine is AGPL-3.0-only (see native/aether/LICENSE).

The NPVS v5 compact-envelope/field mapping and generation-2 white-box table in src-tauri/src/custom/npvs.rs and gen2-wb.bin are adapted from Aether Mobile 1.6.0 and FrontierTM/Pantegnos commit 5a599878c4c113d4d91d1da7294d43095bdb8433 (AGPL-3.0). Upstream: https://github.com/FrontierTM/Pantegnos/tree/5a599878c4c113d4d91d1da7294d43095bdb8433 . Full license: third_party/licenses/Pantegnos-AGPL-3.0.txt.

The newly adapted NPVS decoder/table are not represented as MIT-only merely because the original desktop LICENSE is MIT. Distribution of the combined application requires review of the applicable copyleft obligations and provision of corresponding source. Original copyrights and notices remain in force.

RustCrypto crates implement P-256, PBKDF2, HKDF and ChaCha20-Poly1305; their licenses are recorded by their Cargo manifests and lockfile identities.


Additional mobile-derived SmartPlus plan/memory, uplink governor, connection/metadata and AI policy adaptations retain Aether Mobile contributors' AGPL-3.0-or-later notice (third_party/licenses/Aether-Mobile-NOTICE.txt). The full AGPL text is also included in third_party/licenses/Pantegnos-AGPL-3.0.txt. These adaptations are not claimed as MIT-only; the original desktop MIT notice is preserved for its original files.

QR decoding uses jsQR 1.4.0 (MIT, https://github.com/cozmo/jsQR); QR test fixtures use qrcode-generator 1.4.4 (MIT, https://github.com/kazuhikoarase/qrcode-generator). They are installed from the pinned package lock; their upstream license notices accompany the npm packages. Neither sends user images to a remote service.
