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
    /// A functional-plan directory (optionally with a manifest rate override) with the named runs.
    fn functional(tags: &[&str], tweak: &dyn Fn(&mut Built)) -> Self {
        let d = Self::empty();
        fixture::build_functional_only(&d.0, 3, tags, tweak);
        d
    }
    /// The whole synthetic failure plan.
    fn failure() -> Self {
        let d = Self::empty();
        fixture::build_failure(&d.0, 3);
        d
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
    let at = b
        .frames
        .iter()
        .position(|(_, f)| pcap::is_syn(f) && tcp(f).is_some_and(|t| usize::from(t.dp) == port))
        .unwrap();
    &mut b.frames[at].1
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
    assert!(notes.contains("failure suite of the same stage"), "{notes}");
    assert!(notes.contains("stop_"), "{notes}");
    assert!(
        notes.contains("the spike and the live adapter tests of that stage"),
        "{notes}"
    );
    assert!(notes.contains("VM speed, not physical NIC"), "{notes}");
    assert!(
        notes.contains(
            "VM ceiling with sendqueue is an OPEN finding for the physical NIC stage, never a FAIL"
        ),
        "{notes}"
    );
    assert!(!notes.contains("2B-sendqueue"), "{notes}");
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
fn the_verifier_refuses_a_manifest_with_an_unknown_plan() {
    for bad in ["nonsense", "perfs", "Perf", ""] {
        let d = Dir::empty();
        fixture::build_perf_only(&d.0, 3, &[CELL], &|_| {});
        let p = d.0.join("manifest.json");
        let mut m = read_json(&p).unwrap();
        m["plan"] = json!(bad);
        fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
        let (code, v) = verify_cli(&d);
        assert_eq!(v["overall"], NOT_RUN, "{bad:?}");
        assert_eq!(code, 2, "{bad:?}");
        assert!(
            array(&v["runs"][0]["checks"])
                .iter()
                .any(|c| c["result"] == NOT_RUN && s(&c["name"]).contains("manifest.plan")),
            "{bad:?}"
        );
        // Nothing was verified as a functional plan.
        assert_eq!(array(&v["runs"]).len(), 1);
    }
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
    assert!(
        !bad(&v).iter().any(|b| b.starts_with(FAIL)),
        "{:?}",
        bad(&v)
    );
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
        cell_summary(
            rate,
            rep,
            PASS,
            if rx { 100000.0 } else { 50000.0 + rep as f64 },
            rx,
        )
    });
    let r = row(&perf_summary(&cells), 100000);
    assert_eq!(r["pass"], 5);
    assert_eq!(r["rx_loss"], 2);
    assert_eq!(r["completed"], 3);
    assert_eq!(r["median"]["steady_pps_wire"], 50004.0);
    assert_eq!(r["median"]["cpu_user_ms"], 40.0, "reps 3,4,5 only");
    assert_eq!(r["rxloss_cells"], 2);
    assert_eq!(r["rxloss_steady_pps_wire_median"], 100000.0);
    assert_eq!(
        r["rate_gate"], "OPEN",
        "the burst of the RxLoss cells must not make it MET"
    );
}
#[test]
fn fewer_than_three_completed_pass_cells_leave_the_gate_not_run_even_with_rxloss_passes() {
    let cells = all_cells(|rate, rep| {
        let rx = rate == 100000 && rep <= 3;
        cell_summary(rate, rep, PASS, rate as f64, rx)
    });
    let r = row(&perf_summary(&cells), 100000);
    assert_eq!(
        (r["pass"].as_u64(), r["completed"].as_u64()),
        (Some(5), Some(2))
    );
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
    for foreign in [
        "198.18.0.2:600:open",
        "198.18.0.2:8099:closed",
        "198.18.0.9:80:open",
    ] {
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

// ---- final review I-1: a lab0 drop cannot hide an eno1 frame --------------------------------
#[test]
fn eno1_frame_with_a_lab0_drop_is_fail_and_not_discardable() {
    let d = Dir::clean(CELL);
    d.edit(CELL, "capture.json", |c| {
        c["peer"]["tcpdump"]["dropped_kernel"] = json!(3)
    });
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), INVALID, "drop alone is a discardable INVALID");
    assert!(crate::windows_suite::may_discard(verdict(&v), false));
    d.eno1(
        CELL,
        vec![(fixture::BASE + 4.0, fixture::scanner_syn(80, 40000))],
    );
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert_eq!(v["safety_trip"], true);
    assert!(!crate::windows_suite::may_discard(
        verdict(&v),
        v["behaviour_fail"] == true
    ));
}

// ---- sendqueue evidence (Task 5) ------------------------------------------------------------------
const FAST: &str = "perf.10000.r1";
fn drop_tx_mode(b: &mut Built) {
    b.run["identity"].as_object_mut().unwrap().remove("tx_mode");
}
#[test]
fn missing_tx_mode_in_a_sendqueue_directory_is_fail_not_pass() {
    let d = Dir::cell(CELL, &drop_tx_mode);
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "harness predates sendqueue"), "{:?}", bad(&v));
}
#[test]
fn tx_mode_mismatch_is_fail() {
    let d = Dir::cell(CELL, &|b| b.run["identity"]["tx_mode"] = json!("single"));
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "tx_mode_expected"), "{:?}", bad(&v));
}
#[test]
fn over_budget_calls_fail_the_run() {
    let d = Dir::cell(CELL, &|b| b.run["net"]["tx_over_budget"] = json!(2));
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "call budget breached"), "{:?}", bad(&v));
    // A missing counter is not zero either.
    let d = Dir::cell(CELL, &|b| {
        b.run["net"]
            .as_object_mut()
            .unwrap()
            .remove("tx_over_budget");
    });
    assert_eq!(verdict(&d.summary(CELL)), FAIL);
}
#[test]
fn a_single_mode_run_is_not_judged_by_unmeasured_budget_counters() {
    // Both sides say single: its counters are not measured, so tx_over_budget proves nothing either way.
    let d = Dir::cell(CELL, &|b| {
        b.run["identity"]["tx_mode"] = json!("single");
        b.run["net"]["tx_over_budget"] = json!(5);
    });
    let man = d.0.join("manifest.json");
    let mut m = read_json(&man).unwrap();
    m["tx_mode_expected"] = json!("single");
    fs::write(&man, serde_json::to_vec(&m).unwrap()).unwrap();
    let v = d.summary(CELL);
    assert_eq!(verdict(&v), PASS, "{:?}", bad(&v));
}
#[test]
fn a_fast_cell_without_batches_under_sendqueue_is_fail() {
    let d = Dir::cell(FAST, &|b| b.run["net"]["tx_batches"] = json!(0));
    let v = d.summary(FAST);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(
        has(&v, FAIL, "sendqueue claimed but no batch was transmitted"),
        "{:?}",
        bad(&v)
    );
    // The same counters are fine below 10k pps.
    let d = Dir::cell(CELL, &|b| b.run["net"]["tx_batches"] = json!(0));
    assert_eq!(verdict(&d.summary(CELL)), PASS);
    // And a clean fast cell passes.
    let d = Dir::clean(FAST);
    let v = d.summary(FAST);
    assert_eq!(verdict(&v), PASS, "{:?}", bad(&v));
}
#[test]
fn batch_max_above_cap_is_fail() {
    let d = Dir::cell(FAST, &|b| b.run["net"]["tx_batch_max"] = json!(65));
    let v = d.summary(FAST);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "within tx_batch_cap"), "{:?}", bad(&v));
}
#[test]
fn perf_notes_carry_batch_fields() {
    let d = Dir::clean(FAST);
    let m = &d.summary(FAST)["notes"]["perf"];
    assert_eq!(m["tx_batches"], 782); // 50000 probes in batches of at most 64
    assert_eq!(m["tx_batch_max"], 64);
    assert_eq!(m["tx_batch_cap"], 64);
    assert_eq!(m["tx_over_budget"], 0);
    let mut c = cell_summary(10000, 1, PASS, 10000.0, false);
    c["notes"]["perf"]["tx_batch_max"] = json!(64);
    let sum = perf_summary(&[c]);
    assert_eq!(row(&sum, 10000)["median"]["tx_batch_max"], 64.0);
}
#[test]
fn legacy_directories_without_tx_mode_expected_are_unchanged() {
    let root = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../../docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw");
    let mut compared = 0;
    for plan in ["perf-r1", "failure-r1"] {
        let dir = root.join(plan);
        let man = read_json(dir.join("manifest.json")).unwrap();
        assert!(man.get("tx_mode_expected").is_none(), "{plan}");
        let committed = read_json(dir.join("verdict.json")).unwrap();
        let now = verify_dir(&dir);
        for run in array(&now["runs"]) {
            let tag = s(&run["tag"]);
            // The output shape is the old one too: no batch key in notes.perf.
            for k in [
                "tx_batches",
                "tx_batch_max",
                "tx_batch_cap",
                "tx_over_budget",
            ] {
                assert!(run["notes"]["perf"].get(k).is_none(), "{plan}/{tag}: {k}");
            }
            // Rules (a)-(c) are off without tx_mode_expected: no sendqueue check is even recorded.
            assert!(
                array(&run["checks"]).iter().all(|c| {
                    let n = s(&c["name"]);
                    !n.contains("tx_mode") && !n.contains("call budget") && !n.contains("sendqueue")
                }),
                "{plan}/{tag}"
            );
            // The committed pcaps of some runs are .gz (not decompressed here): those runs cannot be
            // re-judged in place and are skipped; every run with plain pcaps must match its verdict.
            if dir.join("runs").join(tag).join("peer.pcap").is_file() {
                let old = array(&committed["runs"])
                    .iter()
                    .find(|r| r["tag"] == run["tag"])
                    .unwrap();
                assert_eq!(run["verdict"], old["verdict"], "{plan}/{tag}");
                // Report-only on legacy evidence: the real cells (kept as C-ordered captures of the
                // Rust scanner at their own rate) match the generated plan sequence.
                if plan == "perf-r1" {
                    assert_eq!(
                        run["notes"]["perf"]["wire_order_matches_plan"], true,
                        "{plan}/{tag}"
                    );
                }
                compared += 1;
            }
        }
    }
    assert!(compared >= 20, "{compared} runs compared");
    // perf-r1: no medians key for the batch size either (a null would break byte identity).
    let sum = &verify_dir(&root.join("perf-r1"))["perf_summary"];
    for row in array(&sum["rows"]) {
        assert!(row["median"].get("tx_batch_max").is_none(), "{row}");
    }
}

// ---- fix round 1: real report shapes, rule (c) edges, rule (c) edges ---------------------
const C01: &str = "c01_one_addr_port_synack.run1";
fn is_pass(v: &Value) -> bool {
    verdict(v) == PASS
}
#[test]
fn a_functional_run_without_tx_mode_fails_like_a_perf_cell() {
    let d = Dir::functional(&[C01], &drop_tx_mode);
    let v = d.summary(C01);
    assert_eq!(verdict(&v), FAIL, "{:?}", bad(&v));
    assert!(has(&v, FAIL, "harness predates sendqueue"), "{:?}", bad(&v));
    assert!(is_pass(&Dir::functional(&[C01], &|_| {}).summary(C01)));
}
#[test]
fn failed_outcomes_are_status_ok_and_still_judged_by_the_sendqueue_rules() {
    let d = Dir::failure();
    for tag in ["linkloss", "rxloss", "overflow_queue"] {
        let run = read_json(d.run_dir(tag).join("run.json")).unwrap();
        // The shape wire_scan writes for a Failed outcome.
        assert_eq!(run["status"], "ok", "{tag}");
        assert_eq!(run["reason"], "Failed", "{tag}");
        assert!(run["net"].is_object(), "{tag}");
        assert!(
            is_pass(&d.summary(tag)),
            "{tag}: {:?}",
            bad(&d.summary(tag))
        );
        d.sealed(tag, "run.json", |r| r["net"]["tx_over_budget"] = json!(1));
        let v = d.summary(tag);
        assert!(
            has(&v, FAIL, "call budget breached"),
            "{tag}: {:?}",
            bad(&v)
        );
        assert_eq!(verdict(&v), FAIL, "{tag}");
    }
    let d = Dir::failure();
    d.sealed("linkloss", "run.json", |r| {
        r["identity"].as_object_mut().unwrap().remove("tx_mode");
    });
    assert!(has(&d.summary("linkloss"), FAIL, "harness predates"));
}
#[test]
fn refusals_carry_no_tx_mode_and_no_net_block_and_are_not_judged() {
    let d = Dir::failure();
    let man = read_json(d.0.join("manifest.json")).unwrap();
    let mut seen = 0;
    for it in planned(&man) {
        if !["ckpt_refuse", "refuse_completed", "perm_restricted"].contains(&s(&it["kind"])) {
            continue;
        }
        let tag = s(&it["tag"]);
        let run = read_json(d.run_dir(tag).join("run.json")).unwrap();
        assert!(run["identity"].get("tx_mode").is_none(), "{tag}");
        if run["status"] == "error" {
            assert!(run.get("net").is_none(), "{tag}");
        }
        let v = d.summary(tag);
        assert!(is_pass(&v), "{tag}: {:?}", bad(&v));
        assert!(
            array(&v["checks"])
                .iter()
                .all(|c| !s(&c["name"]).contains("tx_mode")),
            "{tag}"
        );
        seen += 1;
    }
    assert!(seen >= 8, "{seen}");
}
#[test]
fn an_ok_report_without_a_net_block_is_not_hidden_by_the_narrowing() {
    // status ok but no net: a scan report whose counters vanished must not skip the checks silently.
    let d = Dir::cell(CELL, &|b| {
        b.run.as_object_mut().unwrap().remove("net");
    });
    assert_ne!(verdict(&d.summary(CELL)), PASS);
}
#[test]
fn rule_c_edges() {
    // Below 10k pps a cell without batches is fine; at 10k it is not; the cap is inclusive.
    let d = Dir::cell("perf.1000.r1", &|b| b.run["net"]["tx_batches"] = json!(0));
    assert!(is_pass(&d.summary("perf.1000.r1")));
    let d = Dir::cell(FAST, &|b| b.run["net"]["tx_batch_max"] = json!(64));
    assert!(is_pass(&d.summary(FAST)));
    let d = Dir::cell(FAST, &|b| b.run["net"]["tx_batch_max"] = json!(65));
    let v = d.summary(FAST);
    assert!(has(&v, FAIL, "within tx_batch_cap"), "{:?}", bad(&v));
    assert!(!has(&v, FAIL, "a batch was transmitted"), "{:?}", bad(&v));
    let d = Dir::cell(FAST, &|b| b.run["net"]["tx_batches"] = json!(0));
    let v = d.summary(FAST);
    assert!(has(&v, FAIL, "a batch was transmitted"), "{:?}", bad(&v));
    // Missing fields are not accepted.
    let d = Dir::cell(FAST, &|b| {
        b.run["identity"]
            .as_object_mut()
            .unwrap()
            .remove("tx_batch_cap");
    });
    assert_eq!(verdict(&d.summary(FAST)), FAIL);
    let d = Dir::cell(FAST, &|b| {
        b.run["net"].as_object_mut().unwrap().remove("tx_batch_max");
    });
    assert_eq!(verdict(&d.summary(FAST)), FAIL);
}

// ---- fix round 2: the wire SYN sequence equals the plan's probe sequence ---------------------------------
const ORDER: &str = "wire SYN sequence equals the plan's probe sequence";
fn syn_positions(b: &Built) -> Vec<usize> {
    (0..b.frames.len())
        .filter(|i| pcap::is_syn(&b.frames[*i].1))
        .collect()
}
fn order_note(v: &Value) -> Value {
    v["notes"]["perf"]["wire_order_matches_plan"].clone()
}
/// Exchange the frames (not the timestamps) of two SYNs: the capture order changes.
fn swap_syn_bytes(b: &mut Built) {
    let p = syn_positions(b);
    let (x, y) = (b.frames[p[10]].1.clone(), b.frames[p[11]].1.clone());
    b.frames[p[10]].1 = y;
    b.frames[p[11]].1 = x;
}
#[test]
fn a_clean_cell_sends_exactly_the_plan_sequence() {
    for tag in [CELL, "perf.1000.r1", FAST] {
        let d = Dir::clean(tag);
        let v = d.summary(tag);
        assert_eq!(verdict(&v), PASS, "{tag}: {:?}", bad(&v));
        assert!(has(&v, PASS, ORDER), "{tag}");
        assert_eq!(order_note(&v), true, "{tag}");
    }
}
#[test]
fn the_generated_sequence_depends_on_the_rate_the_scanner_used() {
    let man = read_json(Dir::clean(CELL).0.join("manifest.json")).unwrap();
    let it = json!({"tag":CELL,"kind":"perf","rate":100,"rep":1});
    let mut args = arg_map(&it, &man, false);
    let a = plan_frames(&args).unwrap();
    assert_eq!(a.len(), 500);
    args.insert("--rate".into(), json!("200"));
    let b = plan_frames(&args).unwrap();
    assert_ne!(a, b);
    let mut sa = a.clone();
    let mut sb = b;
    sa.sort();
    sb.sort();
    assert_eq!(sa, sb, "same probes, other order");
}
#[test]
fn reordered_altered_duplicated_or_missing_syns_are_fail() {
    type Tweak = fn(&mut Built);
    let cases: [(&str, Tweak); 4] = [
        ("swapped", |b| {
            let p = syn_positions(b);
            let (x, y) = (b.frames[p[10]].1.clone(), b.frames[p[11]].1.clone());
            b.frames[p[10]].1 = y;
            b.frames[p[11]].1 = x;
        }),
        ("altered byte", |b| {
            let p = syn_positions(b);
            b.frames[p[20]].1[18] ^= 1; // IP id: still a SYN from the binding, but not the planned frame
        }),
        ("duplicated", |b| {
            let p = syn_positions(b);
            let f = b.frames[p[30]].1.clone();
            b.frames[p[31]].1 = f;
        }),
        ("missing", |b| {
            let p = syn_positions(b);
            b.frames.remove(p[40]);
            tx_sent(b, 499);
        }),
    ];
    for (name, tweak) in cases {
        let d = Dir::cell(CELL, &|b| tweak(b));
        let v = d.summary(CELL);
        assert_eq!(verdict(&v), FAIL, "{name}: {:?}", bad(&v));
        assert!(has(&v, FAIL, ORDER), "{name}: {:?}", bad(&v));
        assert_eq!(order_note(&v), false, "{name}");
    }
}
#[test]
fn a_sequence_built_with_another_rate_is_fail() {
    let d = Dir::cell(CELL, &|b| {
        let mut args = arg_map(
            &json!({"kind":"perf","rate":100}),
            &read_json_manifest(),
            false,
        );
        args.insert("--rate".into(), json!("200"));
        let other = plan_frames(&args).unwrap();
        let p = syn_positions(b);
        for (slot, f) in p.into_iter().zip(other) {
            b.frames[slot].1 = f;
        }
    });
    let v = d.summary(CELL);
    assert!(has(&v, FAIL, ORDER), "{:?}", bad(&v));
}
fn read_json_manifest() -> Value {
    read_json(Dir::clean(CELL).0.join("manifest.json")).unwrap()
}
#[test]
fn an_incomplete_capture_makes_the_order_check_invalid_not_fail() {
    let d = Dir::cell(CELL, &|b| {
        swap_syn_bytes(b);
    });
    witness_dropped(&d, CELL);
    let v = d.summary(CELL);
    assert!(has(&v, INVALID, ORDER), "{:?}", bad(&v));
    assert!(!has(&v, FAIL, ORDER), "{:?}", bad(&v));
}
#[test]
fn an_rx_loss_cell_must_send_a_prefix_of_the_plan() {
    let d = Dir::cell(CELL, &|b| {
        rxloss(b, json!(7));
        let p = syn_positions(b);
        let keep = 300;
        let cut: Vec<usize> = p[keep..].to_vec();
        for i in cut.into_iter().rev() {
            b.frames.remove(i);
        }
        tx_sent(b, keep as u64);
    });
    let v = d.summary(CELL);
    assert!(has(&v, PASS, ORDER), "{:?}", bad(&v));
    // A completed cell with the same cut is missing probes.
    let d = Dir::cell(CELL, &|b| {
        let p = syn_positions(b);
        for i in p[300..].iter().rev() {
            b.frames.remove(*i);
        }
        tx_sent(b, 300);
    });
    assert!(has(&d.summary(CELL), FAIL, ORDER));
}
#[test]
fn without_tx_mode_expected_the_order_is_a_report_only_note() {
    for (swap, want) in [(false, true), (true, false)] {
        let d = Dir::cell(CELL, &|b| {
            if swap {
                swap_syn_bytes(b);
            }
        });
        let man = d.0.join("manifest.json");
        let mut m = read_json(&man).unwrap();
        m.as_object_mut().unwrap().remove("tx_mode_expected");
        fs::write(&man, serde_json::to_vec(&m).unwrap()).unwrap();
        let v = d.summary(CELL);
        assert_eq!(order_note(&v), want);
        assert!(
            !has(&v, FAIL, ORDER) && !has(&v, INVALID, ORDER),
            "{:?}",
            bad(&v)
        );
        assert!(
            array(&v["checks"])
                .iter()
                .all(|c| !s(&c["name"]).contains(ORDER))
        );
    }
}
