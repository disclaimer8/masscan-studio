# Linux lab process ownership. Source from wire-lab.sh; no commands run on load.
# A dedicated session keeps capture/scanner descendants addressable even when
# the suite driver exits before its Rust destructors can run.
SUITE_PGID=""
start_suite_group() {
  local logfile=$1; shift
  setsid "$@" >"$logfile" 2>&1 &
  SUITE_PGID=$!
}
# Signal every process of one session. The driver's short-lived command() children run in their
# own process groups (so a deadline can kill their whole tree), which `kill -- -PGID` of the
# driver's group does not reach; they are all in the driver's session, which is this run's own.
signal_session() {  # signal_session SID SIGNAL
  local sid=$1 sig=$2 d st state ppid pgrp s rest
  for d in /proc/[0-9]*; do
    [ -r "$d/stat" ] || continue
    st=$(cat "$d/stat" 2>/dev/null) || continue
    st=${st##*) }   # comm may contain spaces and parentheses: drop through its last ')'
    read -r state ppid pgrp s rest <<<"$st" || continue
    if [ "${s:-}" = "$sid" ]; then kill "-$sig" "${d#/proc/}" 2>/dev/null || true; fi
  done
}
stop_suite_group() {
  [ -n "$SUITE_PGID" ] || return 0
  local pgid=$SUITE_PGID i
  kill -TERM -- "-$pgid" 2>/dev/null || true
  signal_session "$pgid" TERM
  # Rust command wrappers observe TERM and tear down their own short-lived
  # process groups. Allow their bounded output drains to finish before KILL.
  for i in {1..40}; do
    kill -0 -- "-$pgid" 2>/dev/null || break
    sleep 0.05
  done
  kill -KILL -- "-$pgid" 2>/dev/null || true
  signal_session "$pgid" KILL
  wait "$pgid" 2>/dev/null || true
  SUITE_PGID=""
}
