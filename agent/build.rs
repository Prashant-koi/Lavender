use std::process::Command;
use std::path::PathBuf;
use std::env;
use std::fs;

fn main() {
    // we will tell cargo that if ebpf source changes, rerun this build script
    println!("cargo:rerun-if-changed=../lavender-ebpf/src/main.rs");

    // compile the eBPF crate for the bpf target using nightly toolchain.
    // Build scripts inherit RUSTC from the parent cargo invocation, so we
    // must clear those env vars to avoid accidentally invoking stable rustc.
    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--package", "lavender-ebpf",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
            "--release",
        ])
        .env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .current_dir("../")
        .status()
        .expect("failed to compile lavender-ebpf");

    assert!(status.success(), "lavender-ebpf build failed");

    // Export an absolute path so include_bytes! resolves correctly regardless
    // of the current source file location.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));

    // Prefer the hashed deps artifact because it is the actual object emitted by
    // rustc for the bpf target and is reliably parseable by aya.
    let deps_dir = manifest_dir.join("../target/bpfel-unknown-none/release/deps");
    let mut best: Option<(PathBuf, std::time::SystemTime)> = None;

    if let Ok(entries) = fs::read_dir(&deps_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };

            // Keep only the object-like artifact, skip metadata files.
            if !name.starts_with("lavender_ebpf-")
                || name.ends_with(".d")
                || name.ends_with(".rlib")
                || name.ends_with(".rmeta")
                || name.ends_with(".so")
            {
                continue;
            }

            let modified = match entry.metadata().and_then(|m| m.modified()) {
                Ok(t) => t,
                Err(_) => continue,
            };

            match &best {
                Some((_, t)) if modified <= *t => {}
                _ => best = Some((path, modified)),
            }
        }
    }

    let out = if let Some((path, _)) = best {
        path
    } else {
        // Fallback to the top-level artifact path.
        manifest_dir.join("../target/bpfel-unknown-none/release/lavender-ebpf")
    }
    .canonicalize()
    .expect("compiled lavender-ebpf artifact not found");

    println!("cargo:rustc-env=LAVENDER_EBPF_PATH={}", out.display());
}