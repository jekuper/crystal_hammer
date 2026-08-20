// ch-firewall/build.rs
use std::{env, path::PathBuf, process::Command};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ebpf_dir = manifest_dir.join("../ch-firewall-ebpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let status = Command::new("cargo")
        .current_dir(&ebpf_dir)
        .arg("+nightly")
        .args([
            "build",
            "--release",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
        ])
        // Cargo sets these for build scripts; they override rustup's normal
        // toolchain resolution and would force the child `cargo` onto the
        // same stable toolchain that's running us right now.
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTDOC")
        .status()
        .expect("failed to run cargo for ch-firewall-ebpf");
    assert!(status.success(), "ch-firewall-ebpf build failed");

    let built = ebpf_dir.join("target/bpfel-unknown-none/release/ch-firewall-ebpf");
    std::fs::copy(&built, out_dir.join("ch-firewall-ebpf"))
        .expect("failed to copy eBPF bytecode into OUT_DIR");

    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
}