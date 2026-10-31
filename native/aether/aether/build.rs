// >>> AETHER-APP-PATCH build-provenance
//! Compile-time build provenance for the engine.
//!
//! ## Why this file exists (1.2.8-r5)
//!
//! Rounds r2, r3 and r4 all shipped as `versionName "1.2.8"`, `versionCode 12`,
//! and the engine banner only ever printed the UPSTREAM core version
//! (`Aether v1.8.0`), which is identical in every one of them. Nothing in the
//! app, in the log, or on the release page could tell two revisions apart.
//!
//! That is how the r4 field test came back as "nothing changed": the log proves,
//! by five independent strings, that the APK under test was still the r3 build.
//! The engine printed r3's `netstack buffers=512KB/128KB` line, the r4 netstack
//! telemetry never appeared, the ping probe failed with r3's wording, and 260
//! `updated server` notices arrived unsuppressed by r4's filter. Five rounds of
//! analysis were spent on a binary nobody could identify.
//!
//! From r5 the engine stamps the APP patch level into the binary at compile
//! time. `scripts/build-natives.sh` greps the finished `libaether.so` for the
//! exact string and fails the build if it is missing, CI asserts it again inside
//! the packaged APK, and the app compares its own patch level against the one
//! the engine reports on stdout and shouts if they differ.
//!
//! Net effect: the first two lines of every future log say precisely which build
//! produced it. A stale engine is now impossible to ship and impossible to test
//! by accident.

use std::path::{Path, PathBuf};

/// Walks up from the crate dir looking for the repo-root `PATCHLEVEL` file.
///
/// The crate is compiled out of `.native/aether/aether` (a copy made by
/// `fetch-natives.sh`) as well as from `native/aether/aether` in-tree, so the
/// depth is not fixed. `APP_PATCHLEVEL` in the environment always wins, which is
/// what CI sets.
fn discover_patchlevel() -> String {
    if let Ok(v) = std::env::var("APP_PATCHLEVEL") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return v;
        }
    }

    let mut dir: PathBuf = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(".").to_path_buf());

    for _ in 0..6 {
        let candidate = dir.join("PATCHLEVEL");
        if let Ok(text) = std::fs::read_to_string(&candidate) {
            let v = text.trim().to_string();
            if !v.is_empty() {
                return v;
            }
        }
        if !dir.pop() {
            break;
        }
    }

    // Never silently invent a version. "unstamped" is a loud, greppable value
    // and the app treats it as a hard warning.
    "unstamped".to_string()
}

fn main() {
    let patchlevel = discover_patchlevel();

    // The marker is a single contiguous literal so `grep -a` on the stripped
    // .so finds it. Do not reformat it.
    println!("cargo:rustc-env=AETHER_APP_PATCHLEVEL={patchlevel}");
    println!(
        "cargo:rustc-env=AETHER_BUILD_STAMP=AETHER-BUILD-STAMP:{patchlevel}"
    );

    println!("cargo:rerun-if-env-changed=APP_PATCHLEVEL");
    println!("cargo:rerun-if-changed=../../../PATCHLEVEL");
    println!("cargo:rerun-if-changed=../../PATCHLEVEL");
    println!("cargo:rerun-if-changed=../PATCHLEVEL");
}
// <<< AETHER-APP-PATCH build-provenance
