//! Offline lifecycle check: no namespaces, root privileges or packets.
#[cfg(target_os = "linux")]
#[test]
fn shell_cleanup_stops_descendants_even_after_driver_is_killed() {
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
        .args(["-c", r#"
set -eu
source "$1"
trap stop_suite_group EXIT
start_suite_group "$2/log" sh -c 'sh -c '\''trap "" TERM; echo $$ > "$1/child"; while :; do sleep 1; done'\'' child "$1" & wait' driver "$2"
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
"#])
        .arg("process-group-test")
        .arg(&helper)
        .arg(&dir)
        .output().unwrap();
    let _ = fs::remove_dir_all(dir);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
