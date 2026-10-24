# Linux lab process ownership. Source from wire-lab.sh; no commands run on load.
# A dedicated session keeps capture/scanner descendants addressable even when
# the suite driver exits before its Rust destructors can run.
SUITE_PGID=""
start_suite_group() {
  local logfile=$1; shift
  setsid "$@" >"$logfile" 2>&1 &
  SUITE_PGID=$!
}
stop_suite_group() {
  [ -n "$SUITE_PGID" ] || return 0
  local pgid=$SUITE_PGID i
  kill -TERM -- "-$pgid" 2>/dev/null || true
  # Rust command wrappers observe TERM and tear down their own short-lived
  # process groups. Allow their bounded output drains to finish before KILL.
  for i in {1..40}; do
    kill -0 -- "-$pgid" 2>/dev/null || break
    sleep 0.05
  done
  kill -KILL -- "-$pgid" 2>/dev/null || true
  wait "$pgid" 2>/dev/null || true
  SUITE_PGID=""
}
