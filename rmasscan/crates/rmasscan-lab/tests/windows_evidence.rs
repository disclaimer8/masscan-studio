//! Evidence checks run natively on all supported hosts, without an interpreter.
use rmasscan_lab::verify::verify_dir;
use std::path::Path;

#[test]
fn missing_evidence_never_passes() {
    let missing = std::env::temp_dir().join(format!("rmasscan-missing-{}", std::process::id()));
    assert!(!missing.exists());
    assert_eq!(verify_dir(&missing)["overall"], "NOT RUN");
}

#[test]
#[ignore = "stand artifacts: set RMASSCAN_WINWIRE_RESULTS; no packets are sent"]
fn lab_functional_and_pause_resume_artifacts_verify() {
    let dir = std::env::var("RMASSCAN_WINWIRE_RESULTS")
        .expect("NOT RUN: RMASSCAN_WINWIRE_RESULTS required");
    let result = verify_dir(Path::new(&dir));
    assert_eq!(result["overall"], "PASS", "{result}");
}
