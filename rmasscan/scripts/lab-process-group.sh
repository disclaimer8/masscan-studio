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
  local sid=$1 sig=$2 pid
  # one `ps` call, not a /proc scan with a fork per process (that was slow enough on a busy host to
  # stretch the bounded stops)
  for pid in $(ps -e -o pid= -o sid= 2>/dev/null | awk -v sid="$sid" '$2 == sid { print $1 }'); do
    kill "-$sig" "$pid" 2>/dev/null || true
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

# ---- per-child sessions (LR N2) -------------------------------------------------------------
# Every background helper of wire-lab.sh runs in its own session (`setsid`), so that a process it
# spawns (the capture witness starts tcpdump) stays addressable by the session id = the leader's
# pid, even after the leader itself is gone.
start_bg_session() {  # start_bg_session LOGFILE cmd... ; sets BGPID (= the session id)
  local lf=$1; shift
  setsid "$@" >"$lf" 2>&1 &
  BGPID=$!
}
# Number of live (non-zombie) processes in one session (one `ps` call: scanning /proc from the shell
# costs a fork per process and made the polling loops below overrun their bounds on a busy host).
session_members() {  # session_members SID
  ps -e -o sid= -o stat= 2>/dev/null | awk -v sid="$1" '$1 == sid && $2 !~ /^Z/ { n++ } END { print n + 0 }'
}
# Stop one session. TERM goes to the LEADER only and the leader gets up to GRACE seconds to finish
# (the capture witness waits for quiet, sends its end markers, stops tcpdump and writes its meta:
# a TERM that also reached its tcpdump child would end the capture before it is complete).
# Whatever is still in the session afterwards is TERMed, given 2 s, then KILLed. Returns 0 when the
# session is empty at the end.
stop_session() {  # stop_session SID GRACE_SECONDS
  local sid=$1 grace=$2 i
  [ -n "$sid" ] || return 0
  kill -TERM "$sid" 2>/dev/null || true
  for ((i = 0; i < grace * 20; i++)); do
    [ "$(session_members_leader "$sid")" = 0 ] && break
    sleep 0.05
  done
  signal_session "$sid" TERM
  for ((i = 0; i < 40; i++)); do
    [ "$(session_members "$sid")" = 0 ] && break
    sleep 0.05
  done
  signal_session "$sid" KILL
  wait "$sid" 2>/dev/null || true
  for ((i = 0; i < 40; i++)); do
    [ "$(session_members "$sid")" = 0 ] && return 0
    sleep 0.05
  done
  [ "$(session_members "$sid")" = 0 ]
}
# 1 while the leader process is alive and not a zombie, else 0.
session_members_leader() {  # session_members_leader PID
  local st state
  st=$(cat "/proc/$1/stat" 2>/dev/null) || { echo 0; return; }
  st=${st##*) }
  state=${st%% *}
  case "$state" in "" | Z) echo 0 ;; *) echo 1 ;; esac
}
# Processes anywhere on the host named COMM whose command line mentions PATTERN (a path unique to
# this run, e.g. its output directory): a stray tcpdump of this run shows up here even when it has
# left its session. Prints the count.
stray_processes() {  # stray_processes COMM PATTERN
  local comm=$1 pat=$2 d n=0 cmd
  for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = "$comm" ] || continue
    cmd=$(tr "\0" " " <"$d/cmdline" 2>/dev/null) || continue
    case "$cmd" in *"$pat"*) n=$((n + 1)) ;; esac
  done
  echo "$n"
}
