//! `--plan perf`: plan shape, per-rate scanner arguments and expected counts.
use super::*;

fn perf_man() -> Value {
    json!({"plan":"perf","binding":{"iface":"\\Device\\NPF_{X}","src_ip":"198.18.0.1","src_mac":"52:54:00:04:80:a9","router_mac":"02:57:4c:3d:2e:9b"}})
}
#[test]
fn planned_perf_is_exactly_twenty_runs_in_rep_major_order() {
    let tags: Vec<String> = planned(&json!({"plan":"perf"}))
        .iter()
        .map(|i| s(&i["tag"]).to_string())
        .collect();
    let mut want = Vec::new();
    for rep in 1..=5 {
        for rate in [100, 1000, 10000, 100000] {
            want.push(format!("perf.{rate}.r{rep}"));
        }
    }
    assert_eq!(tags, want);
    assert_eq!(tags.len(), 20);
    assert!(
        planned(&json!({"plan":"perf"}))
            .iter()
            .all(|i| i["kind"] == "perf")
    );
}
#[test]
fn other_plans_are_unchanged_by_perf() {
    assert_eq!(planned(&json!({})).len(), 24);
    assert_eq!(planned(&json!({"plan":"functional"})).len(), 24);
    assert_eq!(planned(&json!({"plan":"failure"})).len(), 18);
}
#[test]
fn per_rate_ports_probes_and_expected_counts() {
    // (rate, last port, expected open, expected closed): 8099 is silent, so it is probed but never answered.
    for (rate, last, open, closed) in [
        (100u64, 500u64, 2usize, 498usize),
        (1000, 5000, 2, 4998),
        (10000, 50000, 10, 49989),
        (100000, 65535, 10, 65524),
    ] {
        let c = perf_case(rate);
        assert_eq!(s(&c["ports"]), format!("1-{last}"));
        assert_eq!(n(&c["syn"]), last as i128);
        assert_eq!(ports(s(&c["ports"])).len() as u64, last);
        let exp = perf_expected(&c);
        assert_eq!(exp.iter().filter(|x| x.ends_with(":open")).count(), open);
        assert_eq!(
            exp.iter().filter(|x| x.ends_with(":closed")).count(),
            closed
        );
        assert!(!exp.iter().any(|x| x.contains(":8099:")));
    }
}
#[test]
fn per_rate_case_args_use_the_functional_binding() {
    let man = perf_man();
    for it in planned(&json!({"plan":"perf"})).iter().take(4) {
        let rate = it["rate"].as_u64().unwrap();
        let args = expected_args(it, &man, &BTreeMap::new()).unwrap();
        let get = |k: &str| {
            args.iter()
                .position(|a| a == k)
                .map(|p| args[p + 1].clone())
                .unwrap()
        };
        assert_eq!(get("--rate"), rate.to_string());
        assert_eq!(get("--ports"), format!("1-{}", (rate * 5).min(65535)));
        assert_eq!(get("--targets"), "198.18.0.2");
        assert_eq!(get("--source-port"), "40000");
        assert_eq!(get("--seed"), "1");
        assert_eq!(get("--wait"), "3");
        assert_eq!(get("--iface"), "\\Device\\NPF_{X}");
        assert_eq!(args.len(), 20, "no extra flags: {args:?}");
        assert!(!args.iter().any(|a| a == "--exclude"));
    }
}

// ---- one perf cell on disk ------------------------------------------------------------------
use super::fixture::{self, Built};
use std::sync::atomic::{AtomicU64, Ordering};

const CELL: &str = "perf.100.r1";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Dir(PathBuf);
impl Dir {
    fn empty() -> Self {
        let p = std::env::temp_dir().join(format!(
            "rmasscan-perf-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn cell(tag: &str, tweak: &dyn Fn(&mut Built)) -> Self {
        let d = Self::empty();
        fixture::build_perf_only(&d.0, 3, &[tag], tweak);
        d
    }
    fn clean(tag: &str) -> Self {
        Self::cell(tag, &|_| {})
    }
    fn run_dir(&self, tag: &str) -> PathBuf {
        self.0.join("runs").join(tag)
    }
    fn edit(&self, tag: &str, file: &str, change: impl FnOnce(&mut Value)) {
        let path = self.run_dir(tag).join(file);
        let mut v = read_json(&path).unwrap();
        change(&mut v);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    }
    fn sealed(&self, tag: &str, file: &str, change: impl FnOnce(&mut Value)) {
        self.edit(tag, file, change);
        fixture::reseal(&self.run_dir(tag));
    }
    /// The full per-run summary, as `windows-verify` records it.
    fn summary(&self, tag: &str) -> Value {
        let man = read_json(self.0.join("manifest.json")).unwrap();
        let fx = read_json(self.0.join("fixtures/manifest.json")).unwrap();
        let it = planned(&man).into_iter().find(|i| i["tag"] == tag).unwrap();
        verify_item(&self.0, &man, &fx, &it, None).0.summary()
    }
    /// The eno1 capture sees `frames`, and capture.json describes that file honestly.
    fn eno1(&self, tag: &str, frames: Frames) {
        let bytes = pcap::encode(&frames);
        fs::write(self.run_dir(tag).join("eno1.pcap"), &bytes).unwrap();
        self.edit(tag, "capture.json", |c| {
            c["eno1"]["pcap"] =
                json!({"sha256":sha(&bytes),"size":bytes.len(),"frames":frames.len()});
            c["eno1"]["tcpdump"]["captured"] = json!(frames.len());
            c["eno1"]["tcpdump"]["received"] = json!(frames.len());
        });
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn verdict(v: &Value) -> &str {
    s(&v["verdict"])
}
/// Names of the checks that did not pass.
fn bad(v: &Value) -> Vec<String> {
    array(&v["checks"])
        .iter()
        .filter(|c| c["result"] != PASS)
        .map(|c| format!("{}: {}", s(&c["result"]), s(&c["name"])))
        .collect()
}
fn has(v: &Value, result: &str, part: &str) -> bool {
    array(&v["checks"])
        .iter()
        .any(|c| c["result"] == result && s(&c["name"]).contains(part))
}
/// Mutate the scanner SYN of `port` (frames 0.. are SYNs in port order).
fn syn_of(b: &mut Built, port: usize) -> &mut Vec<u8> {
    &mut b.frames[port - 1].1
}
fn tx_sent(b: &mut Built, count: u64) {
    b.run["net"]["tx_sent"] = json!(count);
}

#[test]
fn a_clean_completed_cell_passes_and_records_every_metric() {
    let d = Dir::clean(CELL);
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), PASS, "{:?}", bad(&v));
    let m = &v["notes"]["perf"];
    assert_eq!(m["rate"], 100);
    assert_eq!(m["rep"], 1);
    assert_eq!(m["probes"], 500);
    assert_eq!(m["expected_open"], 2);
    assert_eq!(m["expected_closed"], 498);
    assert_eq!(m["transmitted_wire"], 500);
    assert_eq!(m["tx_sent"], 500);
    assert_eq!(m["received_open"], 2);
    assert_eq!(m["received_closed"], 498);
    assert_eq!(m["peer_replies_on_wire"], 500);
    assert_eq!(m["outcome"], "Completed");
    assert_eq!(m["capture_valid"], true);
    assert_eq!(m["rx_loss"], false);
    assert_eq!(m["kernel_drops"], 0);
    assert_eq!(m["rx_packets"], 500);
    assert_eq!(m["cpu_user_ms"], 120);
    assert_eq!(m["cpu_kernel_ms"], 340);
    assert_eq!(m["peak_working_set_bytes"], 25_000_000);
    assert_eq!(m["working_set_bytes_after_join"], 18_000_000);
    assert_eq!(m["join_ms"], 1.5);
    assert_eq!(m["steady_pps_inprocess"], 98.0);
    let wire = m["steady_pps_wire"].as_f64().unwrap();
    assert!((wire - 100.0).abs() < 1.0, "{wire}");
    // drain_s = total_s - last_send_s: the 3 s wait plus the 0.1 s margin of the synthetic run.
    let drain = m["drain_s"].as_f64().unwrap();
    assert!((drain - 3.1).abs() < 0.01, "{drain}");
}

// ---- INVALID: the existing capture-completeness rules apply unchanged -------------------------
#[test]
fn tcpdump_kernel_drops_make_the_cell_invalid() {
    let d = Dir::clean(CELL);
    d.edit(CELL, "capture.json", |c| {
        c["peer"]["tcpdump"]["dropped_kernel"] = json!(3)
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), INVALID, "{:?}", bad(&v));
    assert_eq!(v["behaviour_fail"], false);
    assert!(has(
        &v,
        INVALID,
        "peer capture no drops and all frames accounted"
    ));
}
#[test]
fn captured_not_equal_received_makes_the_cell_invalid() {
    let d = Dir::clean(CELL);
    d.edit(CELL, "capture.json", |c| {
        c["peer"]["tcpdump"]["received"] = json!(10_000)
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), INVALID);
    assert_eq!(v["behaviour_fail"], false);
    assert!(has(
        &v,
        INVALID,
        "peer capture no drops and all frames accounted"
    ));
}
#[test]
fn lab0_counter_window_mismatch_makes_the_cell_invalid() {
    let d = Dir::clean(CELL);
    d.edit(CELL, "capture.json", |c| {
        c["peer"]["counters"]["rx_end"] = json!(1)
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), INVALID);
    assert_eq!(v["behaviour_fail"], false);
    assert!(has(&v, INVALID, "peer interface counter window"));
}
#[test]
fn frames_after_the_end_marker_make_the_cell_invalid() {
    let d = Dir::cell(CELL, &|b| {
        b.frames.push((b.outcome + 10.0, scanner_syn_for_tail()));
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), INVALID, "{:?}", bad(&v));
    assert_eq!(v["behaviour_fail"], false);
    assert!(has(&v, INVALID, "end marker"));
}
fn scanner_syn_for_tail() -> Vec<u8> {
    // Any non-marker frame: a 0x88b6 flood-type frame.
    let mut f = vec![0u8; 60];
    f[12] = 0x88;
    f[13] = 0xb6;
    f
}
#[test]
fn an_old_capture_schema_makes_the_cell_invalid() {
    let d = Dir::clean(CELL);
    d.edit(CELL, "capture.json", |c| c["capture_schema"] = json!(2));
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), INVALID);
    assert_eq!(v["behaviour_fail"], false);
    assert!(has(&v, INVALID, "capture schema not older than manifest"));
}
#[test]
fn a_missing_run_is_not_run() {
    let d = Dir::clean(CELL);
    fs::remove_dir_all(d.run_dir(CELL)).unwrap();
    assert_eq!(verdict(&d.summary(CELL)), NOT_RUN);
}

// ---- FAIL -----------------------------------------------------------------------------------
#[test]
fn a_failed_gate_leg_is_fail_not_invalid() {
    for (file, field, bad_value) in [
        ("status-pre.json", "raw_run_allowed", json!(false)),
        ("status-post.json", "raw_run_allowed", json!(false)),
        ("guest-verify.json", "ok", json!(false)),
    ] {
        let d = Dir::clean(CELL);
        d.sealed(CELL, file, |v| v[field] = bad_value.clone());
        let v = d.summary(CELL);
        assert_eq!(verdict(&v), FAIL, "{file}: {:?}", bad(&v));
        assert_eq!(v["behaviour_fail"], true, "{file}");
        assert!(
            !bad(&v).iter().any(|b| b.starts_with(INVALID)),
            "{file}: gate FAIL, not INVALID"
        );
    }
}
#[test]
fn a_nonzero_guest_verify_exit_is_fail() {
    let d = Dir::clean(CELL);
    d.edit(CELL, "meta.json", |m| m["guest_verify_exit"] = json!(1));
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
}
#[test]
fn a_gate_nonce_that_is_not_this_invocation_is_fail() {
    let d = Dir::clean(CELL);
    d.edit(CELL, "status-pre.json", |m| {
        m["guest_verify_nonce"] = json!("someone-else")
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
}
#[test]
fn eno1_seeing_a_lab_frame_is_fail() {
    let d = Dir::clean(CELL);
    d.eno1(
        CELL,
        vec![(fixture::BASE + 4.0, fixture::scanner_syn(80, 40000))],
    );
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "eno1 saw zero lab packets"));
}
#[test]
fn a_syn_to_another_destination_is_fail() {
    let d = Dir::cell(CELL, &|b| {
        syn_of(b, 7)[30..34].copy_from_slice(&[198, 18, 0, 9])
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "every SYN on the wire"));
}
#[test]
fn a_syn_from_the_wrong_mac_is_fail() {
    let d = Dir::cell(CELL, &|b| {
        syn_of(b, 7)[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1])
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "every SYN on the wire"));
}
#[test]
fn a_syn_from_the_wrong_ip_is_fail() {
    let d = Dir::cell(CELL, &|b| {
        syn_of(b, 7)[26..30].copy_from_slice(&[198, 18, 0, 5])
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "every SYN on the wire"));
}
#[test]
fn a_syn_from_the_wrong_source_port_is_fail() {
    let d = Dir::cell(CELL, &|b| {
        syn_of(b, 7)[34..36].copy_from_slice(&40001u16.to_be_bytes())
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "every SYN on the wire"));
}
#[test]
fn wire_syn_count_differing_from_tx_sent_is_fail() {
    let d = Dir::cell(CELL, &|b| tx_sent(b, 499));
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "wire SYN count equals confirmed TX"));
}
#[test]
fn a_completed_cell_with_a_probe_missing_on_the_wire_is_fail() {
    // Port 7 never reached the wire and the scanner says it sent one fewer: only "each probe once" can see it.
    let d = Dir::cell(CELL, &|b| {
        b.frames.remove(6);
        tx_sent(b, 499);
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "each probe exactly once"));
    assert!(!has(&v, FAIL, "wire SYN count equals"));
}
#[test]
fn a_completed_cell_with_a_duplicated_probe_is_fail() {
    // Port 8 is sent twice and port 7 is not sent at all: the count still equals tx_sent.
    let d = Dir::cell(CELL, &|b| {
        let p8 = b.frames[7].1.clone();
        b.frames[6].1 = p8;
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "each probe exactly once"));
    assert!(!has(&v, FAIL, "wire SYN count equals"));
}
#[test]
fn a_syn_after_the_outcome_is_fail() {
    let d = Dir::cell(CELL, &|b| {
        let extra = (b.outcome + 0.5, fixture::scanner_syn(600, 40000));
        b.frames.push(extra);
        tx_sent(b, 501);
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "no SYN after terminal outcome"));
}
#[test]
fn an_outcome_that_is_neither_completed_nor_rxloss_is_fail() {
    for (reason, detail, exit) in [
        ("Stopped", "", 0),
        ("Failed", "TxUncertain { sent: 30 }", 3),
        ("Failed", "ConsumerTooSlow { capacity: 1 }", 3),
    ] {
        let d = Dir::cell(CELL, &|b| {
            b.run["reason"] = json!(reason);
            b.run["fail_detail"] = json!(detail);
            b.guest_exit = exit;
        });
        let v = d.summary(CELL);
        assert_eq!(verdict(&v), FAIL, "{reason} {detail}: {:?}", bad(&v));
        assert!(has(&v, FAIL, "Completed or Failed(RxLoss)"));
    }
}
fn rxloss(b: &mut Built, drops: Value) {
    b.run["reason"] = json!("Failed");
    b.run["status"] = json!("ok");
    b.run["fail_detail"] = json!(format!("RxLoss {{ kernel_drops: {drops} }}"));
    b.run["rx_health"]["kernel_drops"] = drops.clone();
    b.run["net"]["kernel_drops"] = drops;
    b.guest_exit = 3;
}
#[test]
fn rxloss_with_zero_or_unknown_drops_is_fail() {
    for drops in [json!(0), Value::Null] {
        let d = Dir::cell(CELL, &|b| rxloss(b, drops.clone()));
        let v = d.summary(CELL);
        assert_eq!(verdict(&v), FAIL, "{drops}: {:?}", bad(&v));
        assert!(has(&v, FAIL, "RxLoss run has measured kernel drops"));
    }
}
#[test]
fn completed_with_drops_or_unknown_drops_is_fail() {
    for drops in [json!(5), Value::Null] {
        let d = Dir::cell(CELL, &|b| {
            b.run["rx_health"]["kernel_drops"] = drops.clone();
        });
        let v = d.summary(CELL);
        assert_eq!(verdict(&v), FAIL, "{drops}: {:?}", bad(&v));
        assert!(has(
            &v,
            FAIL,
            "Completed run has measured zero kernel drops"
        ));
    }
    // The handle-level counter counts too.
    let d = Dir::cell(CELL, &|b| b.run["net"]["kernel_drops"] = json!(2));
    assert_eq!(verdict(&d.summary(CELL)), FAIL);
}
#[test]
fn completed_with_a_missing_reply_is_silent_loss_and_fail() {
    let d = Dir::cell(CELL, &|b| {
        let r = b.run["replies"].as_array_mut().unwrap();
        r.pop();
        let n = r.len();
        b.run["reply_total"] = json!(n);
        b.run["reply_unique"] = json!(n);
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "equal listener truth"));
}
#[test]
fn completed_with_a_wrong_open_closed_state_is_fail() {
    let d = Dir::cell(CELL, &|b| {
        let r = b.run["replies"].as_array_mut().unwrap();
        for x in r.iter_mut() {
            if x == "198.18.0.2:80:open" {
                *x = json!("198.18.0.2:80:closed");
            }
        }
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
}
#[test]
fn rxloss_with_measured_drops_is_an_honest_pass() {
    // The scan lost replies, said so with the measured count, and the SYNs on the wire are intact.
    let d = Dir::cell(CELL, &|b| {
        rxloss(b, json!(7));
        let r = b.run["replies"].as_array_mut().unwrap();
        r.truncate(100);
        b.run["reply_total"] = json!(100);
        b.run["reply_unique"] = json!(100);
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), PASS, "{:?}", bad(&v));
    let m = &v["notes"]["perf"];
    assert_eq!(m["rx_loss"], true);
    assert_eq!(m["outcome"], "Failed(RxLoss)");
    assert_eq!(m["kernel_drops"], 7);
    // Recorded, not compared: 100 results are kept as they are.
    assert_eq!(
        m["received_open"].as_u64().unwrap() + m["received_closed"].as_u64().unwrap(),
        100
    );
}
#[test]
fn rxloss_still_has_to_keep_wire_and_tx_consistent() {
    let d = Dir::cell(CELL, &|b| {
        rxloss(b, json!(7));
        tx_sent(b, 400);
    });
    assert_eq!(verdict(&d.summary(CELL)), FAIL);
}

// ---- summary and rate gate ------------------------------------------------------------------
fn cell_summary(rate: u64, rep: u64, verdict: &str, wire: f64, rx_loss: bool) -> Value {
    json!({"tag":format!("perf.{rate}.r{rep}"),"verdict":verdict,"notes":{"perf":{
        "rate":rate,"rep":rep,"rx_loss":rx_loss,
        "steady_pps_wire":wire,"steady_pps_inprocess":wire+1.0,
        "cpu_user_ms":10*rep,"cpu_kernel_ms":20*rep,"peak_working_set_bytes":1000*rep,
        "join_ms":rep as f64,"drain_s":3.0+rep as f64}}})
}
fn row(sum: &Value, rate: u64) -> Value {
    array(&sum["rows"])
        .iter()
        .find(|r| r["rate"] == rate)
        .cloned()
        .unwrap()
}
fn all_cells(f: impl Fn(u64, u64) -> Value) -> Vec<Value> {
    let mut out = vec![];
    for rep in 1..=5 {
        for rate in PERF_RATES {
            out.push(f(rate, rep));
        }
    }
    out
}
#[test]
fn summary_has_one_row_per_rate_with_medians_over_pass_cells() {
    let cells =
        all_cells(|rate, rep| cell_summary(rate, rep, PASS, rate as f64 + rep as f64, false));
    let sum = perf_summary(&cells);
    assert_eq!(array(&sum["rows"]).len(), 4);
    let r = row(&sum, 1000);
    assert_eq!(r["pass"], 5);
    assert_eq!(r["fail"], 0);
    assert_eq!(r["invalid"], 0);
    assert_eq!(r["rx_loss"], 0);
    // reps 1..=5: the median is the third value.
    assert_eq!(r["median"]["steady_pps_wire"], 1003.0);
    assert_eq!(r["median"]["steady_pps_inprocess"], 1004.0);
    assert_eq!(r["median"]["cpu_user_ms"], 30.0);
    assert_eq!(r["median"]["cpu_kernel_ms"], 60.0);
    assert_eq!(r["median"]["peak_working_set_bytes"], 3000.0);
    assert_eq!(r["median"]["join_ms"], 3.0);
    assert_eq!(r["median"]["drain_s"], 6.0);
}
#[test]
fn medians_ignore_cells_that_did_not_pass_and_average_an_even_count() {
    let cells = all_cells(|rate, rep| {
        let v = match rep {
            1 => FAIL,
            2 => INVALID,
            _ => PASS,
        };
        // The failing cells carry wild numbers that must not move the median.
        let wire = if v == PASS { 100.0 * rep as f64 } else { 9e9 };
        cell_summary(rate, rep, v, wire, false)
    });
    let r = row(&perf_summary(&cells), 100);
    assert_eq!(
        (
            r["pass"].as_u64(),
            r["fail"].as_u64(),
            r["invalid"].as_u64()
        ),
        (Some(3), Some(1), Some(1))
    );
    assert_eq!(r["median"]["steady_pps_wire"], 400.0);
    // Four PASS cells (reps 3,4,5 and one more): drop rep 5 to make the count even.
    let cells: Vec<_> = cells
        .into_iter()
        .filter(|c| c["tag"] != "perf.100.r5")
        .collect();
    let r = row(&perf_summary(&cells), 100);
    assert_eq!(r["pass"], 2);
    assert_eq!(r["median"]["steady_pps_wire"], 350.0);
}
#[test]
fn rx_loss_cells_are_counted_and_stay_pass() {
    let cells = all_cells(|rate, rep| {
        cell_summary(rate, rep, PASS, rate as f64, rate == 100000 && rep <= 2)
    });
    let sum = perf_summary(&cells);
    let r = row(&sum, 100000);
    assert_eq!(r["pass"], 5);
    assert_eq!(r["rx_loss"], 2);
    assert_eq!(row(&sum, 100)["rx_loss"], 0);
}
#[test]
fn rate_gate_is_met_within_twenty_percent_and_open_outside() {
    for (wire, want) in [
        (100.0, "MET"),
        (80.0, "MET"),
        (120.0, "MET"),
        (79.9, "OPEN"),
        (120.1, "OPEN"),
        (30.0, "OPEN"),
    ] {
        let cells = all_cells(|rate, rep| {
            cell_summary(
                rate,
                rep,
                PASS,
                if rate == 100 { wire } else { rate as f64 },
                false,
            )
        });
        let sum = perf_summary(&cells);
        assert_eq!(row(&sum, 100)["rate_gate"], want, "{wire}");
        assert_eq!(row(&sum, 1000)["rate_gate"], "MET");
    }
}
#[test]
fn rate_gate_needs_three_pass_cells_else_not_run() {
    let cells = all_cells(|rate, rep| {
        let v = if rate == 10000 && rep > 2 { FAIL } else { PASS };
        cell_summary(rate, rep, v, rate as f64, false)
    });
    let sum = perf_summary(&cells);
    assert_eq!(row(&sum, 10000)["pass"], 2);
    assert_eq!(row(&sum, 10000)["rate_gate"], "NOT RUN");
    assert_eq!(row(&sum, 100)["rate_gate"], "MET");
    // Absent cells count as not run.
    let few: Vec<_> = all_cells(|rate, rep| cell_summary(rate, rep, PASS, rate as f64, false))
        .into_iter()
        .filter(|c| {
            c["tag"] != "perf.100.r1" && c["tag"] != "perf.100.r2" && c["tag"] != "perf.100.r3"
        })
        .collect();
    let r = row(&perf_summary(&few), 100);
    assert_eq!(r["pass"], 2);
    assert_eq!(r["not_run"], 3);
    assert_eq!(r["rate_gate"], "NOT RUN");
}
#[test]
fn summary_notes_name_the_latency_sources_and_the_gate_caveat() {
    let sum = perf_summary(&[]);
    let notes = sum["notes"].to_string();
    assert!(notes.contains("failure-r1"), "{notes}");
    assert!(notes.contains("stop_"), "{notes}");
    assert!(
        notes.contains("2026-10-24-rmasscan-stage2b-windows-spike-raw"),
        "{notes}"
    );
    assert!(notes.contains("VM speed, not physical NIC"), "{notes}");
    assert!(notes.contains("2B-sendqueue"), "{notes}");
    assert!(
        array(&sum["rows"])
            .iter()
            .all(|r| r["rate_gate"] == "NOT RUN")
    );
}

// ---- the whole plan, through the windows-verify entry point -------------------------------------
fn stretch(b: &mut Built, factor: f64) {
    let first = b.frames.iter().map(|f| f.0).fold(f64::INFINITY, f64::min);
    for f in &mut b.frames {
        f.0 = first + (f.0 - first) * factor;
    }
}
fn verify_cli(d: &Dir) -> (i32, Value) {
    let out = d.0.join("verdict.json");
    let code = run(&[
        "--dir".into(),
        d.0.to_string_lossy().into_owned(),
        "--out".into(),
        out.to_string_lossy().into_owned(),
    ])
    .unwrap();
    (code, read_json(out).unwrap())
}
#[test]
fn the_full_synthetic_plan_verifies_pass_with_a_met_gate_at_every_rate() {
    let d = Dir::empty();
    fixture::build_perf(&d.0, 3);
    assert_eq!(fs::read_dir(d.0.join("runs")).unwrap().count(), 20);
    let (code, v) = verify_cli(&d);
    assert_eq!(v["overall"], PASS, "{}", v["totals"]);
    assert_eq!(code, 0);
    assert_eq!(v["totals"][PASS], 21, "manifest plus 20 cells");
    assert_eq!(
        v["groups"],
        json!([]),
        "no pause/resume groups in a perf plan"
    );
    for row in array(&v["perf_summary"]["rows"]) {
        assert_eq!(row["pass"], 5);
        assert_eq!(row["rate_gate"], "MET", "{row}");
    }
}
#[test]
fn an_open_rate_gate_never_changes_overall() {
    // Every cell runs 1.5x slower on the wire than requested: all PASS, every gate OPEN.
    let d = Dir::empty();
    fixture::build_perf_only(&d.0, 3, &[], &|b| stretch(b, 1.5));
    let (code, v) = verify_cli(&d);
    assert_eq!(v["overall"], PASS, "{}", v["totals"]);
    assert_eq!(code, 0);
    for row in array(&v["perf_summary"]["rows"]) {
        assert_eq!(row["rate_gate"], "OPEN", "{row}");
    }
}
#[test]
fn a_failed_cell_fails_overall_and_a_missing_cell_is_not_run() {
    let d = Dir::empty();
    fixture::build_perf(&d.0, 3);
    d.edit("perf.1000.r2", "status-pre.json", |v| {
        v["raw_run_allowed"] = json!(false)
    });
    let (code, v) = verify_cli(&d);
    assert_eq!(v["overall"], FAIL);
    assert_eq!(code, 1);
    assert_eq!(row(&v["perf_summary"], 1000)["fail"], 1);
    assert_eq!(row(&v["perf_summary"], 1000)["pass"], 4);
    fs::remove_dir_all(d.run_dir("perf.100.r5")).unwrap();
    fs::remove_dir_all(d.run_dir("perf.1000.r2")).unwrap();
    let (code, v) = verify_cli(&d);
    assert_eq!(v["overall"], NOT_RUN);
    assert_eq!(code, 2);
    assert_eq!(row(&v["perf_summary"], 100)["not_run"], 1);
}
#[test]
fn a_synthetic_plan_with_a_pass_rx_loss_cell_still_passes_overall() {
    let d = Dir::empty();
    fixture::build_perf_only(&d.0, 3, &[], &|b| {
        if b.run["job"]["rate"] == 100000 {
            rxloss(b, json!(12));
            b.run["replies"].as_array_mut().unwrap().truncate(10);
            b.run["reply_total"] = json!(10);
            b.run["reply_unique"] = json!(10);
        }
    });
    let (_, v) = verify_cli(&d);
    assert_eq!(v["overall"], PASS, "{}", v["totals"]);
    assert_eq!(row(&v["perf_summary"], 100000)["rx_loss"], 5);
    assert_eq!(row(&v["perf_summary"], 100)["rx_loss"], 0);
}
#[test]
fn a_perf_directory_is_refused_by_an_unknown_plan_name() {
    // Plans other than functional, failure and perf plan the functional runs (no perf cells appear).
    assert!(
        planned(&json!({"plan":"nonsense"}))
            .iter()
            .all(|i| i["kind"] != "perf")
    );
}

// ---- fix round 1: I1, an incomplete capture is INVALID and rerunnable ---------------------------
fn drop_one_syn(b: &mut Built) {
    b.frames.remove(6);
}
fn witness_dropped(d: &Dir, tag: &str) {
    d.edit(tag, "capture.json", |c| {
        c["peer"]["tcpdump"]["dropped_kernel"] = json!(1)
    });
}
#[test]
fn a_syn_missing_from_an_incomplete_capture_is_invalid_not_a_behaviour_failure() {
    // The scanner sent all 500 (tx_sent 500); tcpdump says it dropped a frame and port 7 is not in the file.
    let d = Dir::cell(CELL, &drop_one_syn);
    witness_dropped(&d, CELL);
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), INVALID, "{:?}", bad(&v));
    assert_eq!(v["behaviour_fail"], false, "{:?}", bad(&v));
    assert!(crate::windows_suite::may_discard(verdict(&v), false));
    assert!(!bad(&v).iter().any(|b| b.starts_with(FAIL)), "{:?}", bad(&v));
}
#[test]
fn a_syn_missing_from_a_proven_capture_is_still_a_behaviour_fail() {
    let d = Dir::cell(CELL, &|b| {
        drop_one_syn(b);
        tx_sent(b, 499);
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert_eq!(v["behaviour_fail"], true);
    assert!(!crate::windows_suite::may_discard(verdict(&v), true));
}
#[test]
fn one_incomplete_capture_in_the_plan_makes_overall_invalid_and_the_cell_rerunnable() {
    let d = Dir::empty();
    fixture::build_perf_only(&d.0, 3, &[], &|b| {
        if b.tag == "perf.1000.r3" {
            drop_one_syn(b);
        }
    });
    witness_dropped(&d, "perf.1000.r3");
    let (code, v) = verify_cli(&d);
    assert_eq!(v["overall"], INVALID, "{}", v["totals"]);
    assert_eq!(code, 2);
    assert_eq!(v["behaviour_fail"], json!([]));
    assert_eq!(v["totals"][INVALID], 1);
    assert_eq!(
        crate::verify::run_status(&d.0, "perf.1000.r3"),
        (INVALID.to_owned(), false)
    );
}

// ---- fix round 1: M1 and M4, medians and the gate rest on Completed PASS cells only ------------
#[test]
fn medians_and_the_gate_use_completed_pass_cells_and_rxloss_cells_get_their_own_fields() {
    // 100k: reps 1-2 are RxLoss PASS cells with a wild short-burst rate, reps 3-5 Completed and slow.
    let cells = all_cells(|rate, rep| {
        let rx = rate == 100000 && rep <= 2;
        cell_summary(rate, rep, PASS, if rx { 100000.0 } else { 50000.0 + rep as f64 }, rx)
    });
    let r = row(&perf_summary(&cells), 100000);
    assert_eq!(r["pass"], 5);
    assert_eq!(r["rx_loss"], 2);
    assert_eq!(r["completed"], 3);
    assert_eq!(r["median"]["steady_pps_wire"], 50004.0);
    assert_eq!(r["median"]["cpu_user_ms"], 40.0, "reps 3,4,5 only");
    assert_eq!(r["rxloss_cells"], 2);
    assert_eq!(r["rxloss_steady_pps_wire_median"], 100000.0);
    assert_eq!(r["rate_gate"], "OPEN", "the burst of the RxLoss cells must not make it MET");
}
#[test]
fn fewer_than_three_completed_pass_cells_leave_the_gate_not_run_even_with_rxloss_passes() {
    let cells = all_cells(|rate, rep| {
        let rx = rate == 100000 && rep <= 3;
        cell_summary(rate, rep, PASS, rate as f64, rx)
    });
    let r = row(&perf_summary(&cells), 100000);
    assert_eq!((r["pass"].as_u64(), r["completed"].as_u64()), (Some(5), Some(2)));
    assert_eq!(r["rate_gate"], "NOT RUN");
    assert_eq!(row(&perf_summary(&cells), 1000)["rate_gate"], "MET");
}
#[test]
fn a_missing_median_is_not_run_never_open() {
    let cells = all_cells(|rate, rep| {
        let mut c = cell_summary(rate, rep, PASS, rate as f64, false);
        if rate == 1000 {
            c["notes"]["perf"]["steady_pps_wire"] = Value::Null;
        }
        c
    });
    let r = row(&perf_summary(&cells), 1000);
    assert_eq!(r["completed"], 5);
    assert!(r["median"]["steady_pps_wire"].is_null());
    assert_eq!(r["rate_gate"], "NOT RUN");
}

// ---- fix round 1: M3, an RxLoss PASS cell is genuine --------------------------------------------
fn rx_cell(tweak: impl Fn(&mut Built)) -> Dir {
    Dir::cell(CELL, &|b| {
        rxloss(b, json!(7));
        let r = b.run["replies"].as_array_mut().unwrap();
        r.truncate(100);
        b.run["reply_total"] = json!(100);
        b.run["reply_unique"] = json!(100);
        tweak(b);
    })
}
#[test]
fn rxloss_results_must_be_a_subset_of_the_listener_truth() {
    for foreign in ["198.18.0.2:600:open", "198.18.0.2:8099:closed", "198.18.0.9:80:open"] {
        let d = rx_cell(|b| b.run["replies"][0] = json!(foreign));
        let v = d.summary(CELL);
        assert_eq!(verdict(&v), FAIL, "{foreign}: {:?}", bad(&v));
        assert!(has(&v, FAIL, "retained and genuine"), "{foreign}");
    }
}
#[test]
fn rxloss_results_may_not_repeat_an_entry() {
    let d = rx_cell(|b| {
        let first = b.run["replies"][0].clone();
        b.run["replies"][1] = first;
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "retained and genuine"));
}
#[test]
fn rxloss_detail_must_match_the_measured_drops() {
    // fail_detail says 7 drops, rx_health says 9 (net 9): the scanner contradicts itself.
    let d = rx_cell(|b| {
        b.run["rx_health"]["kernel_drops"] = json!(9);
        b.run["net"]["kernel_drops"] = json!(9);
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "exactly measured drop count"));
    // net and rx_health disagreeing is the same contradiction.
    let d = rx_cell(|b| b.run["net"]["kernel_drops"] = json!(8));
    assert_eq!(verdict(&d.summary(CELL)), FAIL);
}
#[test]
fn rxloss_must_exit_three() {
    let d = rx_cell(|b| b.guest_exit = 0);
    assert_eq!(verdict(&d.summary(CELL)), FAIL);
}
#[test]
fn a_genuine_rxloss_cell_still_passes() {
    let d = rx_cell(|_| {});
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), PASS, "{:?}", bad(&v));
}
