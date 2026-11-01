//! Offline package acceptance is also selected by the existing --all-targets runner.
use std::{path::PathBuf, process::Command};

#[test]
fn packaged_public_consumer_and_native_tls_crud() {
    run_fixture("package_smoke.py");
}

#[test]
fn native_fixture_process_ownership() {
    run_fixture("test_package_lifecycle.py");
}

fn run_fixture(script: &str) {
    let status = Command::new("python3")
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join(script),
        )
        .status()
        .expect("start package smoke; Python 3 is a test prerequisite");
    assert!(
        status.success(),
        "packaged artifact acceptance failed: {status}"
    );
}
