//! Offline lifecycle check: no namespaces, root privileges or packets. Linux only: it needs
//! `setsid` and `/proc`, so it cannot run on macOS and runs in the Linux CI job.
#[cfg(target_os = "linux")]
fn cleanup_outlives_check(driver_script: &str) -> std::process::Output {
    use std::{fs, path::Path, process::Command, time::SystemTime};
    let dir = std::env::temp_dir().join(format!(
        "rmasscan-process-group-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/lab-process-group.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
set -eu
source "$1"
trap stop_suite_group EXIT
start_suite_group "$2/log" sh -c "$3" driver "$2"
for i in {1..100}; do [ -s "$2/child" ] && break; sleep 0.02; done
test -s "$2/child"
child=$(cat "$2/child")
kill -KILL "$SUITE_PGID"
wait "$SUITE_PGID" 2>/dev/null || true
stop_suite_group
for i in {1..100}; do
  state=$(ps -o stat= -p "$child" || true)
  case "$state" in ""|Z*) exit 0;; esac
  sleep 0.02
done
echo "descendant $child survived cleanup" >&2
exit 1
"#,
        ])
        .arg("process-group-test")
        .arg(&helper)
        .arg(&dir)
        .arg(driver_script)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(dir);
    output
}

/// A TERM-ignoring descendant in the driver's own process group.
#[cfg(target_os = "linux")]
#[test]
fn shell_cleanup_stops_descendants_even_after_driver_is_killed() {
    let output = cleanup_outlives_check(
        r#"sh -c 'trap "" TERM; echo $$ > "$1/child"; while :; do sleep 1; done' child "$1" & wait"#,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The driver's command() children run in their OWN process group (`set -m` gives a background
/// job its own group in a non-interactive shell). Killing the driver's group does not reach
/// them; the session sweep must.
#[cfg(target_os = "linux")]
#[test]
fn shell_cleanup_stops_descendants_that_sit_in_their_own_process_group() {
    let output = cleanup_outlives_check(
        r#"set -m; sh -c 'trap "" TERM; echo $$ > "$1/child"; while :; do sleep 1; done' child "$1" & wait"#,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
