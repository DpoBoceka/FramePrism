// Link against libjpeg-turbo from the COMMITTED pinned prefix
// <repo>/deps/.jpeg-prefix (the byte-contract build input — the same
// prefix the CI oracle-anchored path builds against, so the dev
// build-fact line reads the same fact as ci's):
//   - libturbojpeg.a (TurboJPEG tj3 API, used by src/codec.rs)
//   - libjpeg.a     (raw libjpeg C API, used by src/tileenc.rs via the
//                    opaque-handle shim ljpeg_shim.c — the jpeg_* struct
//                    layouts are internal, so the shim hides them)
// The committed prefix is a darwin AppleClang build; on other hosts a
// link failure is expected and named — there is no other default.
// JPEG_TURBO_PREFIX=/path/to/prefix is the EXPLICIT opt-in to a
// different prefix (e.g. the UNPATCHED Homebrew formula at
// /opt/homebrew/opt/jpeg-turbo — a named non-contract path: it silently
// emits merged-DHT output, which is why it is never the default).
// A missing/unresolvable prefix is a NAMED build refusal at build time —
// never a silent fallback to another location.

use std::path::PathBuf;

fn main() {
    // The default prefix is the COMMITTED repo prefix (CARGO_MANIFEST_DIR
    // is tool/; the prefix sits at <repo>/deps/.jpeg-prefix).
    let repo_prefix = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("deps")
        .join(".jpeg-prefix");
    let (prefix, via) = match std::env::var("JPEG_TURBO_PREFIX")
        .ok()
        .filter(|p| !p.is_empty())
    {
        Some(p) => (PathBuf::from(p), "the JPEG_TURBO_PREFIX env var"),
        None => (repo_prefix.clone(), "the committed repo prefix (the default)"),
    };
    let prefix_abs = match std::fs::canonicalize(&prefix) {
        Ok(p) => p,
        Err(e) => {
            // Named refusal: the prefix does not exist. Never fall back.
            println!(
                "cargo:error=frameprism build refusal: the resolved JPEG_TURBO_PREFIX ({}) — {} — does not exist ({}). Nothing to link; build.rs never falls back to another location. Remedy: build the committed prefix with deps/build-libjpeg.sh (the pinned source fetches via deps/fetch.sh), or point JPEG_TURBO_PREFIX at an existing prefix (the committed one is {}).",
                prefix.display(),
                via,
                e,
                repo_prefix.display(),
            );
            std::process::exit(1);
        }
    };
    let libdir = prefix_abs.join("lib");
    // The include dir handed to the C compiler is the UN-canonicalized
    // resolved path when the resolved prefix is absolute: on Windows
    // std::fs::canonicalize returns the \\?\ extended-length verbatim
    // path, which MSVC cl.exe's include lookup rejects (C1083 on the
    // shim's jpeglib.h include); the un-canonicalized dir is the form the
    // compiler's path handling accepts on every host (the same handling
    // the shim source path gets, passed un-canonicalized below). A
    // relative opt-in keeps the canonicalized form (its pre-existing
    // behavior — the documented opt-in is an absolute path, and the
    // contract default is always absolute). The canonicalized prefix_abs
    // stays the authority for the existence checks, the named refusals,
    // the link surface, and the build-fact line (the absolute path must
    // stay visible for pin-drift).
    let incdir = if prefix.is_absolute() {
        prefix.join("include")
    } else {
        prefix_abs.join("include")
    };

    // Named refusal: the resolved prefix must carry the link surface
    // (lib/ + include/ + the two static libs), however it was resolved.
    let mut missing: Vec<String> = Vec::new();
    if !libdir.is_dir() {
        missing.push("lib/ (the static library dir)".to_string());
    } else {
        for name in ["libturbojpeg.a", "libjpeg.a"] {
            if !libdir.join(name).is_file() {
                missing.push(format!("lib/{name} (the static lib)"));
            }
        }
    }
    if !incdir.is_dir() {
        missing.push("include/ (the headers dir)".to_string());
    }
    if !missing.is_empty() {
        println!(
            "cargo:error=frameprism build refusal: the resolved JPEG_TURBO_PREFIX ({}) — {} — is missing: {}. Nothing to link; build.rs never falls back to another location. Remedy: build the committed prefix with deps/build-libjpeg.sh (the pinned source fetches via deps/fetch.sh), or point JPEG_TURBO_PREFIX at an existing prefix (the committed one is {}).",
            prefix_abs.display(),
            via,
            missing.join(", "),
            repo_prefix.display(),
        );
        std::process::exit(1);
    }

    // Compile the raw-libjpeg lossless shim (opaque handles; public API only).
    let shim = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ljpeg_shim.c");
    let mut cc = cc::Build::new();
    cc.include(&incdir)
        .file(&shim)
        .opt_level(2)
        .compile("ljpeg_shim");

    println!("cargo:rustc-link-search=native={}", libdir.display());
    println!("cargo:rustc-link-lib=turbojpeg");
    println!("cargo:rustc-link-lib=jpeg");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", libdir.display());
    println!("cargo:rerun-if-env-changed=JPEG_TURBO_PREFIX");
    println!("cargo:rerun-if-changed={}", shim.display());

     // The jpeg-turbo BUILD line for the reports (the early-packaging
    // work, maintainer decision: the codec-version block of the run/
    // per-clip reports). A build-time fact — the linked libjpeg.a
    // exports no version symbol — read from the prefix's pkgconfig
    // Version: lines. Purely additive (the prefix resolution above is
    // untouched): the line carries the ABSOLUTE prefix path because the
    // pin-drift risk is two same-version builds from different prefixes
    // (an explicit JPEG_TURBO_PREFIX opt-in vs the project-pinned
    // deps/.jpeg-prefix) — same version string from a different prefix
    // is a different byte contract, and the line must make that visible
    // in every report. Fallback when a .pc is missing/unreadable:
    // "unknown (prefix …)" — named, never silent.
    let pc_version = |name: &str| -> Option<String> {
        let p = prefix_abs.join("lib").join("pkgconfig").join(name);
        std::fs::read_to_string(p)
            .ok()
            .and_then(|text| {
                text.lines()
                    .find(|l| l.starts_with("Version:"))
                    .map(|l| l.trim_start_matches("Version:").trim().to_string())
                    .filter(|v| !v.is_empty())
            })
    };
    let build_line = match pc_version("libturbojpeg.pc").or_else(|| pc_version("libjpeg.pc")) {
        Some(v) => format!("libjpeg-turbo {v} (prefix {})", prefix_abs.display()),
        None => format!("unknown (prefix {})", prefix_abs.display()),
    };
    println!("cargo:rustc-env=FRAMEPRISM_JPEG_TURBO_BUILD={build_line}");
    println!("cargo:rerun-if-changed={}/lib/pkgconfig/libturbojpeg.pc", prefix_abs.display());
    println!("cargo:rerun-if-changed={}/lib/pkgconfig/libjpeg.pc", prefix_abs.display());

    // The in-process container crates' versions (the
    // bake container is built with the `tar` + `zstd` crates, no
    // system-tool subprocess): the sidecar version fields report
    // `tar <crate version> (in-process)` / `zstd <libzstd version>
    // (in-process)` (the zstd value is the RUNTIME
    // `zstd::ZSTD_versionString()` — the bundled libzstd), and the
    // pin rows assert their expected against the value embedded HERE
    // (the crate versions, read from the committed Cargo.lock — the
    // lock IS the pin; a missing entry or a name/version pair the
 // lock does not carry is a NAMED build refusal, the project
    // convention, never a silent default). The `fstool` entry is the
 // same class ( — the in-process ISO writer for `bake
    // --iso`: the version the pin row asserts + the bake summary's
    // build-fact line key off it).
    let lock = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let crate_version = |name: &str| -> Option<String> {
        std::fs::read_to_string(&lock).ok().and_then(|text| {
            let mut lines = text.lines();
            while let Some(l) = lines.next() {
                if l == format!("name = \"{name}\"") {
                    return lines
                        .next()
                        .and_then(|v| v.strip_prefix("version = "))
                        .map(|v| v.trim_matches('"').to_string())
                        .filter(|v| !v.is_empty());
                }
            }
            None
        })
    };
    for name in ["tar", "zstd", "fstool"] {
        let var = format!("FRAMEPRISM_{}_CRATE_VERSION", name.to_uppercase());
        match crate_version(name) {
            Some(v) => println!("cargo:rustc-env={var}={v}"),
            None => {
                println!(
                    "cargo:error=frameprism build refusal: the committed Cargo.lock ({}) carries no `name = \"{name}\"` + `version =` pair — the in-process {name} crate version cannot be embedded (the sidecar version fields + the pin rows key off it). Remedy: restore the committed lock (cargo add {name} against the pinned version).",
                    lock.display()
                );
                std::process::exit(1);
            }
        }
    }
    println!("cargo:rerun-if-changed={}", lock.display());
}
