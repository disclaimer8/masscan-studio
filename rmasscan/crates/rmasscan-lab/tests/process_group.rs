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
    let helper = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../scripts/lab-process-group.sh");
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

// ---- LR N2: wire-lab.sh background helpers run in their own session -----------------------------

/// Runs `body` in bash with the helper sourced and a scratch dir in `$d`.
#[cfg(target_os = "linux")]
fn session_script(files: &[(&str, &str)], body: &str) -> std::process::Output {
    use std::{fs, path::Path, process::Command, time::SystemTime};
    let dir = std::env::temp_dir().join(format!(
        "rmasscan-session-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    for (name, text) in files {
        fs::write(dir.join(name), text).unwrap();
    }
    let helper = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../scripts/lab-process-group.sh");
    let output = Command::new("bash")
        .args(["-c", &format!("set -eu\nsource \"$1\"\nd=$2\n{body}")])
        .arg("session-test")
        .arg(&helper)
        .arg(&dir)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(dir);
    output
}

/// A fake capture witness: it starts a TERM-proof child (the "tcpdump"), and on TERM takes a
/// moment to finalise (writes `fin`) before it exits, leaving the child behind unless somebody
/// sweeps the session.
#[cfg(target_os = "linux")]
const WITNESS: &str = r#"#!/bin/sh
d=$1
sh -c 'trap "" TERM; echo $$ > "$1/child"; while :; do sleep 1; done' tcpdump "$d" &
trap 'sleep 0.6; echo done > "$d/fin"; exit 0' TERM
while :; do sleep 0.05; done
"#;

#[cfg(target_os = "linux")]
const SESSION_ASSERTS: &str = r#"
child=$(cat "$d/child")
[ "$(session_members "$sid")" = 0 ] || { echo "session $sid still has members" >&2; exit 1; }
state=$(ps -o stat= -p "$child" || true)
case "$state" in ""|Z*) ;; *) echo "child $child survived" >&2; exit 1;; esac
"#;

#[cfg(target_os = "linux")]
#[test]
fn a_termed_witness_gets_time_to_finalise_and_leaves_no_child() {
    let body = format!(
        r#"start_bg_session "$d/log" sh "$d/witness.sh" "$d"
sid=$BGPID
for i in {{1..100}}; do [ -s "$d/child" ] && break; sleep 0.02; done
test -s "$d/child"
stop_session "$sid" 10
test -s "$d/fin" || {{ echo "the witness was killed before it finalised" >&2; exit 1; }}
{SESSION_ASSERTS}"#
    );
    let out = session_script(&[("witness.sh", WITNESS)], &body);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_witness_that_ignores_term_is_killed_after_the_grace_with_its_child() {
    let deaf = WITNESS.replace(
        "trap 'sleep 0.6; echo done > \"$d/fin\"; exit 0' TERM",
        "trap '' TERM",
    );
    let body = format!(
        r#"start_bg_session "$d/log" sh "$d/witness.sh" "$d"
sid=$BGPID
for i in {{1..100}}; do [ -s "$d/child" ] && break; sleep 0.02; done
test -s "$d/child"
start=$SECONDS
stop_session "$sid" 1
[ $((SECONDS - start)) -le 8 ] || {{ echo "stop_session overran its grace" >&2; exit 1; }}
{SESSION_ASSERTS}"#
    );
    let out = session_script(&[("witness.sh", &deaf)], &body);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_stray_process_of_this_run_is_counted_by_name_and_path() {
    let body = r#"printf '#!/bin/sh\nwhile :; do sleep 1; done\n' >"$d/fakedump"; chmod +x "$d/fakedump"
[ "$(stray_processes fakedump "$d")" = 0 ]
"$d/fakedump" & p=$!
sleep 0.2
[ "$(stray_processes fakedump "$d")" = 1 ] || { echo "not counted" >&2; exit 1; }
[ "$(stray_processes fakedump /nonexistent-run)" = 0 ]
kill -KILL "$p"; wait "$p" 2>/dev/null || true
[ "$(stray_processes fakedump "$d")" = 0 ]
"#;
    let out = session_script(&[], body);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// wire-lab.sh must use those helpers: every background child in its own session, a bounded
/// leader-first stop, and a stray check before it reports a clean namespace count.
#[test]
fn wire_lab_cleanup_uses_session_stops_and_checks_for_strays() {
    let text = std::fs::read_to_string(
        std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../../scripts/wire-lab.sh"),
    )
    .unwrap();
    let cleanup = text
        .split("cleanup() {")
        .nth(1)
        .and_then(|t| t.split("\ntrap cleanup EXIT").next())
        .expect("cleanup()");
    assert!(
        cleanup.contains("stop_session"),
        "cleanup must stop sessions"
    );
    assert!(!cleanup.contains("sleep 0.3"), "no 0.3 s TERM-to-KILL race");
    let stray = cleanup
        .find("stray_processes")
        .expect("stray check in cleanup");
    let left = cleanup
        .find("namespaces_left=")
        .expect("namespaces_left log");
    assert!(
        stray < left,
        "the stray check precedes the clean-count log line"
    );
    assert!(
        text.contains("start_bg_session"),
        "start_bg must run children in their own session"
    );
}
