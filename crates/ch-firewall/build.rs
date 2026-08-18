// ch-firewall/build.rs
use std::{env, path::PathBuf, process::Command};

fn main() {
    // Only meaningful on Linux — nothing to build for other hosts.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ebpf_dir = manifest_dir.join("../ch-firewall-ebpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let status = Command::new("cargo")
        .current_dir(&ebpf_dir)
        .args([
            "build",
            "--release",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
        ])
        .env_remove("RUSTUP_TOOLCHAIN") // force the nightly toolchain pinned in ch-firewall-ebpf/rust-toolchain.toml
        .status()
        .expect("failed to run cargo for ch-firewall-ebpf");
    assert!(status.success(), "ch-firewall-ebpf build failed");

    let built = ebpf_dir
        .join("target/bpfel-unknown-none/release/ch-firewall-ebpf");
    std::fs::copy(&built, out_dir.join("ch-firewall-ebpf"))
        .expect("failed to copy eBPF bytecode into OUT_DIR");

    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
}