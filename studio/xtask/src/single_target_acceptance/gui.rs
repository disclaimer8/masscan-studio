//! Independent packet/GUI/history consistency and conservative terminal windows.
use super::*;
use studio_protocol::{Status, acceptance::QUIET_NS, single_target::acceptance::Attempt};
#[derive(Serialize)]
pub struct Checked {
    packets: Verified,
    durable_results: BTreeMap<u16, bool>,
    late_replies: usize,
    unanswered_at_completion: Vec<u16>,
}
pub fn verify(bytes: &[u8], attempt: &Attempt) -> Result<Checked> {
    attempt.validate()?;
    let report = NetworkReport::decode(&attempt.report)?;
    let packets = super::verify_evidence(bytes, &report)?;
    let (metadata, pcap) = super::export(bytes)?;
    let witness = &metadata.completion.witness;
    let clock = metadata
        .completion
        .measurements
        .timeline
        .as_ref()
        .ok_or("Capture lacks precise clock coverage")?;
    clock.validate()?;
    if metadata.permit != attempt.ticket.permit
        || witness.nonce != attempt.ticket.capture_nonce
        || witness.process.pid != attempt.ticket.capture_pid
        || witness.created != attempt.ticket.capture_created
        || clock.ready.high()? >= attempt.start.low()?
        || attempt
            .joined
            .high()?
            .checked_add(QUIET_NS)
            .ok_or("Quiet time overflow")?
            >= clock.stopped.low()?
    {
        return Err("GUI/capture identity, readiness or terminal quiet window differs".into());
    }
    let identity: studio_platform::unix::Identity =
        serde_json::from_str(&attempt.process_identity).map_err(|e| e.to_string())?;
    if identity.pid != attempt.driver_pid
        || identity.uid != attempt.driver_uid
        || identity.birth == [0, 0]
        || !identity.executable.is_absolute()
    {
        return Err("GUI process identity differs".into());
    }
    let permit = &metadata.permit;
    let mac = report.destinations[&permit.target];
    let mut results = BTreeMap::new();
    let mut late_replies = 0;
    for packet in super::super::network_acceptance::witness::frames(pcap)? {
        match classify(packet.frame, permit, mac)? {
            Frame::Syn { .. } | Frame::ArpRequest => {
                if packet.time_ns.saturating_sub(1000) <= attempt.start.high()?
                    || packet
                        .time_ns
                        .checked_add(1000)
                        .ok_or("Packet clock overflow")?
                        >= attempt.terminal.low()?
                {
                    return Err("Scanner packet outside unambiguous active GUI window".into());
                }
            }
            Frame::Reply { port, open, .. } => {
                if packet
                    .time_ns
                    .checked_add(1000)
                    .ok_or("Packet clock overflow")?
                    < attempt.terminal.low()?
                {
                    results.insert(port, open);
                } else if packet.time_ns.saturating_sub(1000) > attempt.terminal.high()? {
                    late_replies += 1;
                } else {
                    return Err("Response timing is ambiguous at GUI completion".into());
                }
            }
            _ => {}
        }
    }
    let saved: BTreeMap<_, _> = attempt.rows.iter().map(|r| (r.port, r.open)).collect();
    if saved != results {
        return Err("Saved GUI results differ from captured responses before completion".into());
    }
    Ok(Checked {
        packets,
        unanswered_at_completion: permit
            .ports
            .iter()
            .copied()
            .filter(|p| !results.contains_key(p))
            .collect(),
        durable_results: results,
        late_replies,
    })
}
pub fn command(evidence: &str, gui: &str, history: &str) -> super::super::Result<()> {
    let bytes = read(
        evidence,
        super::super::network_acceptance::witness::MAX_CAPTURE + 16385,
    )?;
    let attempt = Attempt::decode(&read(
        gui,
        studio_protocol::single_target::acceptance::MAX_GUI_EVIDENCE,
    )?)?;
    let checked = verify(&bytes, &attempt)?;
    if !Path::new(history).join("history.sqlite3").is_file() {
        return Err("Existing GUI history required".into());
    }
    verify_history(Path::new(history), &attempt)?;
    println!("{}", serde_json::to_string_pretty(&checked)?);
    Ok(())
}

fn verify_history(history: &Path, attempt: &Attempt) -> super::super::Result<()> {
    use rusqlite::{Connection, OpenFlags, params};
    let db = Connection::open_with_flags(
        history.join("history.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    db.execute_batch("BEGIN;")?;
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    let count: i64 = db.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))?;
    let matched: bool = db.query_row(
        "SELECT id=?1 AND attempt=?2 AND job=?3 AND status=?4 AND checkpoint IS NULL AND next_index IS NULL AND network_report=?5 FROM scans LIMIT 1",
        params![attempt.scan.as_slice(), attempt.attempt.as_slice(), serde_json::to_string(&attempt.ticket.permit.job())?, serde_json::to_string(&Status::Completed)?, &attempt.report],
        |r| r.get(0))?;
    if integrity != "ok" || count != 1 || !matched {
        return Err("Independent history read differs from GUI evidence".into());
    }
    let mut query = db.prepare("SELECT scan,ip,port,open FROM results LIMIT 5")?;
    let raw = query
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u16>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut rows = Vec::new();
    for (scan, ip, port, open) in raw {
        if scan != attempt.scan || ![0, 1].contains(&open) {
            return Err("Invalid independently saved result".into());
        }
        rows.push(studio_protocol::Row {
            ip,
            port,
            open: open == 1,
        });
    }
    let mut expected = attempt.rows.clone();
    rows.sort_by_key(|r| (r.ip.clone(), r.port));
    expected.sort_by_key(|r| (r.ip.clone(), r.port));
    if rows != expected {
        return Err("Independent saved rows differ from GUI evidence".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use studio_platform::single_target::{
        CaptureCompletion, CaptureFinish, CaptureStatistics, CaptureTimeline, CaptureWitness,
    };
    use studio_protocol::{Row, acceptance::Stamp, single_target::acceptance::Ticket};
    fn stamp(ms: u64, origin: u64) -> Stamp {
        Stamp {
            wall_ns: ms * 1_000_000,
            mono_ns: (ms - origin) * 1_000_000,
            uncertainty_ns: 0,
        }
    }
    fn hash(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    struct Fixture {
        permit: Permit,
        completion: CaptureCompletion,
        pcap: Vec<u8>,
        attempt: Attempt,
        frames: Vec<Vec<u8>>,
    }
    impl Fixture {
        fn new() -> Self {
            let (mut permit, report, frames) = super::super::tests::setup();
            permit.created = 999;
            let pcap = super::super::tests::pcap(&super::super::tests::spaced(&frames));
            let completion = CaptureCompletion {
                witness: CaptureWitness {
                    generation: permit.generation.clone(),
                    nonce: "2".repeat(32),
                    permit_sha256: hash(&serde_json::to_vec(&permit).unwrap()),
                    created: 999,
                    process: studio_platform::unix::Identity {
                        uid: 0,
                        pid: 123,
                        birth: [1, 2],
                        executable: studio_platform::macos::installed_path(&permit.tooling_sha256)
                            .unwrap(),
                    },
                    lease_file: [1, 2],
                },
                finished: 1008,
                measurements: CaptureFinish {
                    elapsed_millis: 9100,
                    recorded: 6,
                    statistics: Some(CaptureStatistics {
                        received: 6,
                        dropped: 0,
                        interface_dropped: 0,
                    }),
                    error: None,
                    timeline: Some(CaptureTimeline {
                        opened: stamp(999000, 999000),
                        ready: stamp(999100, 999000),
                        stopped: stamp(1008000, 999000),
                        closed: stamp(1008100, 999000),
                        samples: (999000..=1008000)
                            .step_by(500)
                            .map(|ms| stamp(ms, 999000))
                            .chain([stamp(1008100, 999000)])
                            .collect(),
                    }),
                },
                pcap_bytes: pcap.len() as u64,
                pcap_sha256: hash(&pcap),
            };
            let identity = studio_platform::unix::Identity {
                uid: permit.owner_uid,
                pid: 321,
                birth: [3, 4],
                executable: "/test/package/studio-ui".into(),
            };
            let attempt = Attempt {
                ticket: Ticket {
                    permit: permit.clone(),
                    capture_nonce: "2".repeat(32),
                    capture_pid: 123,
                    capture_created: 999,
                },
                driver_pid: 321,
                driver_uid: permit.owner_uid,
                process_identity: serde_json::to_string(&identity).unwrap(),
                ui_sha256: "e".repeat(64),
                driver_started: stamp(999200, 999200),
                start: stamp(999500, 999200),
                terminal: stamp(1005000, 999200),
                joined: stamp(1005200, 999200),
                samples: (999200..=1005200)
                    .step_by(100)
                    .map(|ms| stamp(ms, 999200))
                    .collect(),
                scan: [1; 16],
                attempt: [2; 16],
                status: Status::Completed,
                report: report.encode().unwrap(),
                rows: vec![],
                displayed_rows: 0,
                displayed_results: vec![],
                sent: 4,
            };
            Self {
                permit,
                completion,
                pcap,
                attempt,
                frames,
            }
        }
        fn envelope(&self) -> Vec<u8> {
            let mut bytes = serde_json::to_vec(
                &serde_json::json!({"permit":self.permit,"completion":self.completion}),
            )
            .unwrap();
            assert!(bytes.len() <= 16384);
            bytes.push(b'\n');
            bytes.extend_from_slice(&self.pcap);
            bytes
        }
        fn records(&mut self, records: Vec<(u64, Vec<u8>)>) {
            self.pcap = super::super::tests::pcap(&records);
            self.completion.pcap_bytes = self.pcap.len() as u64;
            self.completion.pcap_sha256 = hash(&self.pcap);
            let count = records.len() as u64 + 2;
            self.completion.measurements.recorded = count;
            self.completion
                .measurements
                .statistics
                .as_mut()
                .unwrap()
                .received = count as u32;
        }
    }
    #[test]
    fn silent_completion_has_exact_four_probes_and_zero_saved_states() {
        let f = Fixture::new();
        let checked = verify(&f.envelope(), &f.attempt).unwrap();
        assert!(checked.durable_results.is_empty());
        assert_eq!(checked.unanswered_at_completion, f.permit.ports);
        assert_eq!(checked.packets.probes, 4);
        Attempt::decode(&serde_json::to_vec(&f.attempt).unwrap()).unwrap();
    }
    #[test]
    fn live_response_matches_saved_state_and_late_response_is_distinct() {
        for late in [false, true] {
            let mut f = Fixture::new();
            let port = u16::from_be_bytes(f.frames[0][36..38].try_into().unwrap());
            let mut records = super::super::tests::spaced(&f.frames);
            records.push((
                if late {
                    1_006_000_000_000
                } else {
                    1_001_100_000_000
                },
                super::super::tests::reply(&f.frames[0], true, true),
            ));
            records.sort_by_key(|(ns, _)| *ns);
            f.records(records);
            if !late {
                f.attempt.rows.push(Row {
                    ip: f.permit.target.to_string(),
                    port,
                    open: true,
                });
                f.attempt.displayed_rows = 1;
                f.attempt.displayed_results = f.attempt.rows.clone();
            }
            let checked = verify(&f.envelope(), &f.attempt).unwrap();
            assert_eq!(checked.late_replies, usize::from(late));
            assert_eq!(
                checked.durable_results.get(&port),
                if late { None } else { Some(&true) }
            );
            f.attempt.rows = vec![Row {
                ip: f.permit.target.to_string(),
                port,
                open: !late,
            }];
            f.attempt.displayed_rows = 1;
            f.attempt.displayed_results = f.attempt.rows.clone();
            if !late {
                f.attempt.rows[0].open = false;
                f.attempt.displayed_results = f.attempt.rows.clone();
            }
            assert!(verify(&f.envelope(), &f.attempt).is_err());
        }
    }
    #[test]
    fn mismatched_identity_counts_clocks_results_and_quiet_window_cannot_pass() {
        for kind in 0..17 {
            let mut f = Fixture::new();
            match kind {
                0 => f.attempt.ticket.capture_nonce = "3".repeat(32),
                1 => f.attempt.ticket.capture_pid += 1,
                2 => f.attempt.sent = 3,
                3 => f.attempt.status = Status::Stopped,
                4 => f.attempt.displayed_rows = 1,
                5 => f.completion.measurements.timeline = None,
                6 => {
                    f.completion.measurements.timeline.as_mut().unwrap().stopped =
                        stamp(1007000, 999000)
                }
                7 => {
                    f.completion.measurements.timeline.as_mut().unwrap().ready =
                        stamp(999500, 999000)
                }
                8 => {
                    f.completion.measurements.timeline.as_mut().unwrap().samples[1].wall_ns +=
                        20_000_000
                }
                9 => f.attempt.samples[1].wall_ns += 20_000_000,
                10 => {
                    f.attempt.samples.drain(1..20);
                }
                11 => {
                    f.completion
                        .measurements
                        .timeline
                        .as_mut()
                        .unwrap()
                        .samples
                        .drain(1..6);
                }
                12 => f.attempt.driver_pid += 1,
                13 => {
                    f.attempt.rows.push(Row {
                        ip: f.permit.target.to_string(),
                        port: 80,
                        open: false,
                    });
                    f.attempt.displayed_rows = 1;
                    f.attempt.displayed_results = f.attempt.rows.clone();
                }
                14 => f.attempt.start = stamp(1001000, 999200),
                15 => f.attempt.terminal = stamp(1004000, 999200),
                _ => f.attempt.driver_uid += 1,
            }
            assert!(
                verify(&f.envelope(), &f.attempt).is_err(),
                "mutation {kind}"
            );
        }
    }
    #[test]
    fn independent_sqlite_read_rejects_substitution_without_mutating_history() {
        use studio_protocol::{Envelope, Event};
        let f = Fixture::new();
        let dir = std::env::temp_dir().join(format!(
            "studio-single-gui-db-{}",
            studio_protocol::id_text(studio_protocol::new_id().unwrap())
        ));
        let mut store = studio_store::Store::open(&dir).unwrap();
        store
            .begin(f.attempt.scan, f.attempt.attempt, &f.permit.job(), false)
            .unwrap();
        for (index, event) in [
            Event::NetworkPrepared {
                bytes: f.attempt.report.clone(),
            },
            Event::Started { total: "4".into() },
            Event::Finished {
                status: Status::Completed,
                detail: "done".into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            store
                .apply(&Envelope::new(
                    [3; 16],
                    f.attempt.scan,
                    f.attempt.attempt,
                    index as u64 + 1,
                    event,
                ))
                .unwrap();
        }
        drop(store);
        let path = dir.join("history.sqlite3");
        let before = std::fs::read(&path).unwrap();
        verify_history(&dir, &f.attempt).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute(
            "INSERT INTO results(scan,ip,port,open) VALUES(?1,?2,80,0)",
            rusqlite::params![f.attempt.scan.as_slice(), f.permit.target.to_string()],
        )
        .unwrap();
        drop(db);
        assert!(verify_history(&dir, &f.attempt).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn same_count_visible_state_substitution_is_rejected() {
        let mut f = Fixture::new();
        f.attempt.rows = vec![Row {
            ip: f.permit.target.to_string(),
            port: 80,
            open: true,
        }];
        f.attempt.displayed_results = f.attempt.rows.clone();
        f.attempt.displayed_results[0].open = false;
        f.attempt.displayed_rows = 1;
        assert!(f.attempt.validate().unwrap_err().contains("Visible GUI"));
    }
    #[test]
    fn ambiguous_response_at_completion_is_not_silently_credited_or_discarded() {
        let mut f = Fixture::new();
        let mut records = super::super::tests::spaced(&f.frames);
        records.push((
            f.attempt.terminal.wall_ns,
            super::super::tests::reply(&f.frames[0], true, false),
        ));
        f.records(records);
        assert!(verify(&f.envelope(), &f.attempt).is_err());
    }
}
