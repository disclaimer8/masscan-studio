//! Independent checks for restart and network interruption windows. No I/O to networks.
use super::*;

struct Window {
    checks: Run,
    safety: Run,
    wire: Wire,
    history: Value,
    smoke: Value,
    extra: Value,
    chron: Option<Chronicle>,
    end: f64,
}
fn job(stage: &str) -> Value {
    json!({"targets":PEER_IP,"ports":if stage=="guard" {"8000-8255"} else {"8000-8031"},"seed":"2","rate":4,"exclusions":"","backend":"MacFeth"})
}
fn read_window(d: &Path, head: Option<&str>, stage: &str) -> Window {
    let (mut safety, safe, extra) = super::safety(d, head);
    let mut r = run_of(stage);
    let w = read_json(d.join("window.json")).unwrap_or(Value::Null);
    let sm = read_json(d.join("smoke.json")).unwrap_or(Value::Null);
    let history = read_json(d.join("history.json")).unwrap_or(Value::Null);
    r.inv(
        "window and chronicle name the expected stage",
        w["stage"] == stage && sm["stage"] == stage,
        stage,
    );
    let c = load_chronicle(&mut r, &sm);
    if let Some(c) = &c {
        coverage_checks(&mut safety, &safe.caps, c);
        let select = format!("Select:{}", s(&sm["plan"][0]["scan_id_hex"]));
        let expected: Vec<&str> = match stage {
            "pause" => vec!["Authorize", "Start:restart", "Pause", "Lock"],
            "resume" => vec!["Authorize", &select, "Resume", "Lock"],
            _ => vec!["Authorize", "Start:guard", "Lock"],
        };
        session_checks(&mut r, c, &expected);
    }
    r.inv(
        "peer witness is complete",
        safe.peer_proven,
        "missing/incomplete peer capture",
    );
    let wire = safe.peer.as_ref().map_or_else(Wire::default, classify);
    rogue_check(&mut r, &wire);
    r.beh(
        "exactly one planned and saved scan",
        array(&sm["plan"]).len() == 1 && scans_of(&history).len() == 1,
        "",
    );
    let rec = &sm["plan"][0];
    let scan = &history["scans"][0];
    r.beh(
        "fixed acceptance job in chronicle and history",
        rec["job"] == job(stage) && scan["job"] == job(stage),
        "",
    );
    r.beh(
        "scan identity matches",
        is_hex(s(&scan["scan_id_hex"]), 32) && scan["scan_id_hex"] == rec["scan_id_hex"],
        "",
    );
    r.inv(
        "chronicle records a process ID",
        sm["process_id"].as_u64().is_some_and(|n| n > 0),
        "",
    );
    let ui_pids = array(&w["pids"])
        .iter()
        .filter(|p| p["name"] == "ui")
        .collect::<Vec<_>>();
    r.inv(
        "chronicle PID matches the spawned UI",
        ui_pids.len() == 1 && ui_pids[0]["pid"] == sm["process_id"],
        "",
    );
    let status = match stage {
        "pause" => "Paused",
        "resume" => "Completed",
        _ => "Interrupted",
    };
    r.beh(
        "terminal status matches stage",
        scan["status"] == status && rec["finished_status"] == status,
        "",
    );
    let start = c.as_ref().and_then(|c| {
        c.actions
            .iter()
            .find(|a| a.name.starts_with("Start:") || a.name == "Resume")
    });
    let terminal = c.as_ref().and_then(|c| {
        c.events.iter().find(|e| {
            e.kind == "State" && e.status == status && start.is_some_and(|a| e.mono >= a.mono)
        })
    });
    r.beh("terminal state follows action", terminal.is_some(), "");
    let end = terminal.map_or(0.0, |e| e.utc);
    r.beh(
        "all SYNs inside the active stage",
        start.is_some_and(|a| {
            wire.syns
                .iter()
                .all(|y| y.t >= a.utc - CLOCK_TOLERANCE_S && y.t <= end + STOP_SYN_GRACE_S)
        }),
        "",
    );
    let expected = plan_frames_for_job(&job(stage)).unwrap_or_default();
    let offset = if stage == "resume" {
        read_json(d.join("history-before.json"))
            .and_then(|v| v["scans"][0]["next_index"].as_u64())
            .unwrap_or(u64::MAX)
    } else {
        0
    };
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    let planned = expected.get(offset..).unwrap_or_default();
    let prefix = wire.syns.len() <= planned.len()
        && wire
            .syns
            .iter()
            .zip(planned)
            .all(|(y, f)| tcp(f).is_some_and(|t| y.port == t.dp && y.seq == t.seq));
    r.beh(
        "SYN order and cookies equal the planned continuation",
        !wire.syns.is_empty() && prefix,
        "",
    );
    if stage == "resume" {
        r.beh(
            "resume sends the whole remaining plan",
            offset > 0 && offset < expected.len() && wire.syns.len() == planned.len(),
            "",
        );
    } else {
        r.beh(
            "stage stops before completing the plan",
            wire.syns.len() < expected.len(),
            "",
        );
    }
    if stage == "pause" {
        let k = scan["next_index"].as_u64();
        r.beh(
            "durable checkpoint equals the sent prefix",
            scan["checkpoint_len"].as_u64().is_some_and(|n| n > 0)
                && k == Some(wire.syns.len() as u64)
                && rec["paused_next_index"] == scan["next_index"],
            "",
        );
        let pause = c
            .as_ref()
            .and_then(|c| c.actions.iter().find(|a| a.name == "Pause"));
        r.beh("pause is ACKed within five seconds", matches!((pause,terminal),(Some(a),Some(e)) if e.detail==PAUSE_ACK_TEXT && (0..=PAUSE_TO_PAUSED_MAX_MS).contains(&(e.mono-a.mono))), "");
    } else {
        r.beh(
            "terminal history has no checkpoint",
            scan["checkpoint_len"] == 0 && scan["next_index"].is_null(),
            "",
        );
    }
    if stage == "guard" {
        let change = read_json(d.join("guard-change.json")).unwrap_or(Value::Null);
        let ready = read_json(d.join("guard-ready.json")).unwrap_or(Value::Null);
        let removed = parse_utc(s(&change["removed_utc"]));
        let restored = parse_utc(s(&change["restored_utc"]));
        let ready_at = parse_utc(s(&ready["utc"]));
        r.inv(
            "lab ARP change and restoration recorded",
            change["schema"] == 1
                && change["interface"] == PEER_IF
                && change["source_ip"] == SCANNER_IP
                && change["remove_exit"] == 0
                && change["restore_exit"] == 0,
            "",
        );
        r.beh(
            "guard-ready belongs to this UI process",
            ready["pid"] == sm["process_id"] && ready["schema"] == 1,
            "",
        );
        r.beh("ARP guard interrupts within five seconds of removal", matches!((ready_at, removed, restored, terminal), (Some(a),Some(b),Some(c),Some(e)) if a<=b && b<=e.utc+CLOCK_TOLERANCE_S && e.utc-b<=5.0+CLOCK_TOLERANCE_S && c>=e.utc && e.detail.starts_with("Attempt interrupted:") && e.detail.contains("ARP")), "");
        r.inv(
            "witnesses include restoration",
            restored.is_some_and(|t| {
                safe.caps
                    .iter()
                    .all(|c| c.stop.is_some_and(|end| end >= t + 1.0))
            }),
            "",
        );
    }
    Window {
        checks: r,
        safety,
        wire,
        history,
        smoke: sm,
        extra,
        chron: c,
        end,
    }
}
pub(super) fn verify(d: &Path, pause: Option<&Path>, head: Option<&str>) -> Value {
    let stage = read_json(d.join("window.json"))
        .and_then(|v| v["stage"].as_str().map(str::to_owned))
        .unwrap_or_default();
    if !matches!(stage.as_str(), "pause" | "resume" | "guard")
        || (pause.is_some() && stage != "resume")
    {
        let mut r = run_of("stage");
        r.inv("known stage required", false, stage);
        return finish(vec![(r, None)], Value::Null, Map::new(), false);
    }
    let mut w = read_window(d, head, &stage);
    let mut runs = vec![];
    let mut notes = Map::new();
    if stage == "resume" {
        if let Some(p) = pause {
            let mut first = read_window(p, head, "pause");
            let first_rows = history_checks(&mut first.checks, &first.history["scans"][0]);
            results_checks(
                &mut first.checks,
                &first_rows,
                &Recv {
                    syns: &first.wire.syns,
                    replies: &first.wire.replies,
                    end: first.end,
                    exempt_after: None,
                },
                false,
                &mut notes,
            );
            let before = read_json(d.join("history-before.json")).unwrap_or(Value::Null);
            let previous = &first.history["scans"][0];
            let current = &w.history["scans"][0];
            w.checks.beh(
                "saved history identical before new process",
                before == first.history,
                "scans, checkpoint metadata and existing rows",
            );
            let hash = text_in(p, "data.sha256");
            w.checks.inv(
                "SQLite hash links the two processes",
                hash.is_some() && hash == text_in(d, "data-before.sha256"),
                "",
            );
            w.checks.beh(
                "fresh UI process and engine attempt",
                w.smoke["process_id"] != first.smoke["process_id"]
                    && current["attempt_hex"] != previous["attempt_hex"]
                    && is_hex(s(&current["attempt_hex"]), 32)
                    && w.smoke["prior_attempt_hex"] == previous["attempt_hex"],
                "",
            );
            w.checks.beh(
                "same scan identity survives restart",
                current["scan_id_hex"] == previous["scan_id_hex"],
                "",
            );
            w.checks.inv(
                "same binaries and source in both windows",
                w.extra["provenance"] == first.extra["provenance"],
                "",
            );
            w.checks.beh("first session closed before next authorization",matches!((&first.chron,&w.chron),(Some(a),Some(b)) if chronicle_span(a).zip(chronicle_span(b)).is_some_and(|((_,end),(start,_))|end<start)),"");
            w.wire.syns.splice(0..0, first.wire.syns);
            w.wire.replies.splice(0..0, first.wire.replies);
            runs.push((first.safety, None));
            runs.push((first.checks, None));
        } else {
            w.checks.add(
                "pause window required for restart proof",
                NOT_RUN,
                "use --pause-dir",
                false,
            );
        }
    }
    let rows = history_checks(&mut w.checks, &w.history["scans"][0]);
    results_checks(
        &mut w.checks,
        &rows,
        &Recv {
            syns: &w.wire.syns,
            replies: &w.wire.replies,
            end: w.end,
            exempt_after: None,
        },
        false,
        &mut notes,
    );
    runs.push((w.safety, None));
    runs.push((w.checks, None));
    finish(runs, w.extra, notes, false)
}
