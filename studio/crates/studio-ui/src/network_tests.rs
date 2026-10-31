use super::*;
use studio_app::{NetworkCoverage, NetworkReadiness};
use studio_protocol::{Envelope, Event, NetworkReport};

fn report(all_missing: bool) -> (Job, NetworkReport) {
    let mut job = Job::example(Backend::MacNetwork);
    job.targets = "10.0.0.0-10.0.0.3,10.0.0.1".into();
    job.exclusions = "10.0.0.3".into();
    job.ports = "80,80,90-91".into();
    let a = "10.0.0.1".parse().unwrap();
    let b = "10.0.0.2".parse().unwrap();
    let report = NetworkReport {
        job_digest: job.original_digest().unwrap(),
        routes: rmasscan_net::PhysicalRoutePlan {
            interface_name: "en0".into(),
            interface_index: 4,
            source_ipv4: "10.0.0.254".parse().unwrap(),
            source_mac: Some([2, 1, 2, 3, 4, 5]),
            next_hops: [(a, a), (b, b)].into(),
            excluded: [(
                "10.0.0.0".parse().unwrap(),
                rmasscan_net::ExcludedReason::NetworkAddress,
            )]
            .into(),
        },
        destinations: if all_missing {
            Default::default()
        } else {
            [(a, [2, 1, 1, 1, 1, 1])].into()
        },
        unresolved: if all_missing { vec![a, b] } else { vec![b] },
    };
    (job, report)
}

#[test]
fn physical_draft_preview_counts_unions_and_user_exclusions_without_an_adapter() {
    let (job, _) = report(false);
    let counts = studio_app::requested_counts(&job).unwrap();
    assert_eq!((counts.targets, counts.ports, counts.probes), (4, 3, 12));
    let text = network_ui::preview(&job).unwrap();
    assert!(text.contains("Requested: 4 addresses / 12 probes"));
    assert!(text.contains("Candidates after your exclusions: 3 addresses / 9 probes"));
    assert!(text.contains("eligible targets require neighbour preparation"));
    let mut broad = job;
    broad.targets = "0.0.0.0/0,10.0.0.1".into();
    broad.exclusions = "0.0.0.0-10.0.0.0,10.0.0.3-255.255.255.255".into();
    broad.ports = "1-65535,80".into();
    let counts = studio_app::requested_counts(&broad).unwrap();
    assert_eq!(
        (counts.targets, counts.probes),
        (4_294_967_296, 281_470_681_743_360)
    );
    assert!(
        network_ui::preview(&broad)
            .unwrap()
            .contains("2 addresses / 131070 probes")
    );
    broad.rate = 0;
    assert!(network_ui::preview(&broad).is_err());
}

#[test]
fn route_success_does_not_enable_closed_physical_start_or_authorize_a_session() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().unwrap();
    let job = Job::example(Backend::MacNetwork);
    fill_settings(&ui, &job);
    ui.set_backend_index(2);
    ui.set_job_valid(true);
    ui.set_mac_network_supported(true);
    ui.set_mac_network_open(false);
    let readiness = NetworkReadiness {
        job_digest: Some(job.original_digest().unwrap()),
        backend: Backend::MacNetwork,
        checking: false,
        route_ready: true,
        execution_enabled: false,
        detail: "Interface en0, source 10.0.0.254; 2 direct, 0 routed; BPF not checked".into(),
    };
    network_ui::readiness(&ui, Some(&readiness));
    assert!(
        ui.get_network_detail()
            .contains("Read-only route check passed")
    );
    assert!(ui.get_network_detail().contains("does not authorize"));
    assert!(!ui.get_authorized());
    assert!(!ui.get_can_start());
    ui.set_job_targets("10.0.0.77".into());
    network_ui::readiness(&ui, Some(&readiness));
    assert!(
        !ui.get_network_detail().contains("passed"),
        "queued route readiness for an older draft must not reappear after editing"
    );
    assert!(!network_ui::profile_hint(false, false).contains("disabled in this build"));
    assert!(network_ui::profile_hint(false, false).contains("macOS only"));
    assert!(network_ui::profile_hint(true, false).contains("disabled in this build"));
    ui.set_mac_network_supported(false);
    ui.set_mac_network_open(true);
    assert!(!ui.get_can_start());
    network_ui::readiness(&ui, None);
    assert!(!ui.get_network_checking());
    assert!(!ui.get_network_detail().contains("passed"));
}

#[test]
fn preparing_keeps_stop_available_and_pause_disabled_until_tcp_scanning() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().unwrap();
    for (status, preparing, pause) in [
        ("Starting", false, false),
        ("Preparing network", true, false),
        ("Scanning", false, true),
        ("Saving", false, false),
    ] {
        ui.set_process_active(true);
        ui.set_process_status(status.into());
        ui.set_process_preparing(preparing);
        assert!(ui.get_can_stop());
        assert_eq!(ui.get_can_pause(), pause);
        assert!(!ui.get_can_start());
    }
    ui.set_process_stopping(true);
    assert!(!ui.get_can_stop());
    assert!(!ui.get_can_pause());
    ui.set_authorization_available(true);
    assert!(
        matches!(network_ui::session_action(&ui).unwrap(), Action::Lock),
        "Lock cancels an active preparation, even before authorization state is displayed"
    );
    ui.set_process_active(false);
    let job = Job::example(Backend::MacNetwork);
    fill_settings(&ui, &job);
    assert!(
        matches!(network_ui::session_action(&ui).unwrap(), Action::AuthorizeFor(j) if j == job)
    );
}

#[test]
fn saved_partial_and_all_missing_coverage_survive_reopen_and_programmatic_fill() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().unwrap();
    let path = std::env::temp_dir().join(format!(
        "studio-ui-coverage-{}",
        studio_protocol::id_text(studio_protocol::new_id().unwrap())
    ));
    {
        let mut store = studio_store::Store::open(&path).unwrap();
        for all_missing in [false, true] {
            let (job, report) = report(all_missing);
            let scan = [if all_missing { 2 } else { 1 }; 16];
            store.begin(scan, [3; 16], &job, false).unwrap();
            store
                .apply(&Envelope::new(
                    [4; 16],
                    scan,
                    [3; 16],
                    1,
                    Event::NetworkPrepared {
                        bytes: report.encode().unwrap(),
                    },
                ))
                .unwrap();
        }
    }
    let store = studio_store::Store::open(&path).unwrap();
    let edits = Rc::new(Cell::new(0));
    let count = edits.clone();
    ui.on_draft_changed(move || count.set(count.get() + 1));
    for saved in store.scans().unwrap() {
        let value = NetworkCoverage::from_saved(&saved).unwrap().unwrap();
        let snapshot = network_ui::coverage(&ui, Some(&value)).unwrap();
        // Same order as History restoration. Programmatic fills must not enqueue
        // SetDraft behind the restored coverage update.
        fill_settings(&ui, &saved.job);
        i_slint_backend_testing::mock_elapsed_time(Duration::from_millis(50));
        assert_eq!(edits.get(), 0);
        assert!(ui.get_has_network_coverage());
        assert!(
            ui.get_coverage_summary()
                .contains("requested 4 addresses / 12 probes")
        );
        assert!(
            ui.get_coverage_summary()
                .contains("candidates 3 addresses / 9 probes")
        );
        assert!(
            ui.get_coverage_summary()
                .contains("effective 2 addresses / 6 probes")
        );
        assert!(
            ui.get_coverage_details()
                .contains("10.0.0.0 · automatically excluded: subnet network address")
        );
        assert!(
            ui.get_coverage_details()
                .contains("10.0.0.2 · not scanned: no neighbour response")
        );
        assert_eq!(snapshot.original_job.targets, saved.job.targets);
        assert!(ui.get_empty_title().contains("see scan coverage"));
        let json = studio_inspection::json_with_coverage(&[], Some(&snapshot)).unwrap();
        let exported: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(exported["rows"], serde_json::json!([]));
        assert_eq!(exported["coverage"]["requested"]["targets"], 4);
        if value.eligible_targets == 0 {
            assert!(ui.get_coverage_details().contains("no TCP engine started"));
            assert_eq!(snapshot.unresolved.len(), 2);
        }
    }
    ui.invoke_settings_edited();
    assert_eq!(edits.get(), 1, "explicit edits still notify the controller");
    network_ui::coverage(&ui, None);
    assert!(!ui.get_has_network_coverage());
    assert!(ui.get_coverage_summary().is_empty());
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn history_edit_profile_and_repeat_keep_selected_coverage_with_filtered_and_zero_row_exports() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().unwrap();
    let path = std::env::temp_dir().join(format!(
        "studio-ui-draft-export-{}",
        studio_protocol::id_text(studio_protocol::new_id().unwrap())
    ));
    {
        let mut store = studio_store::Store::open(&path).unwrap();
        store
            .save_profile(None, "Other draft", &Job::example(Backend::Simulation))
            .unwrap();
        for all_missing in [false, true] {
            let (job, report) = report(all_missing);
            let scan = [if all_missing { 2 } else { 1 }; 16];
            store.begin(scan, [3; 16], &job, false).unwrap();
            store
                .apply(&Envelope::new(
                    [4; 16],
                    scan,
                    [3; 16],
                    1,
                    Event::NetworkPrepared {
                        bytes: report.encode().unwrap(),
                    },
                ))
                .unwrap();
            if !all_missing {
                store
                    .apply(&Envelope::new(
                        [4; 16],
                        scan,
                        [3; 16],
                        2,
                        Event::Results(
                            [80, 90]
                                .map(|port| studio_protocol::Row {
                                    ip: "10.0.0.1".into(),
                                    port,
                                    open: true,
                                })
                                .into(),
                        ),
                    ))
                    .unwrap();
            }
        }
    }
    let store = studio_store::Store::open(&path).unwrap();
    let profile = store.profiles().unwrap().into_iter().next().unwrap();
    let cache = Rc::new(RefCell::new(None));
    let actions = Rc::new(RefCell::new(Vec::new()));
    let sent = actions.clone();
    let weak = ui.as_weak();
    ui.on_draft_changed(move || {
        if let Some(ui) = weak.upgrade() {
            sent.borrow_mut().push(network_ui::changed_draft(&ui));
        }
    });
    for saved in store.scans().unwrap() {
        let value = NetworkCoverage::from_saved(&saved).unwrap().unwrap();
        let original = network_ui::coverage(&ui, Some(&value)).unwrap();
        *cache.borrow_mut() = Some(original.clone());
        let rows = Rows {
            observations: RefCell::new(HashMap::new()),
            hosts: RefCell::new(HashMap::new()),
            table: RefCell::new(Table::new(0)),
            keys: RefCell::new(HashMap::new()),
            notify: ModelNotify::default(),
            summary_dirty: Cell::new(true),
            simulation: Cell::new(false),
            archived: Cell::new(false),
        };
        let mut observations = store.observations(saved.scan).unwrap();
        // Keep the observed clock collision deterministic: plain "80" also
        // matches the discovered-time column of the port90 row.
        for observation in &mut observations {
            observation.discovered_at = Some("2026-10-31T10:00:25.580Z".into());
        }
        rows.add(observations);
        rows.table.borrow_mut().filter("80 tcp");
        rows.table.borrow_mut().sort(0, true);
        let expected_rows = rows.export_rows();
        assert_eq!(
            expected_rows.len(),
            usize::from(value.eligible_targets != 0)
        );
        for flow in ["edit", "profile load", "repeat"] {
            fill_settings(&ui, &saved.job);
            network_ui::readiness(
                &ui,
                Some(&NetworkReadiness {
                    job_digest: Some(saved.job.original_digest().unwrap()),
                    backend: Backend::MacNetwork,
                    checking: false,
                    route_ready: true,
                    execution_enabled: false,
                    detail: "saved draft route check".into(),
                }),
            );
            assert!(ui.get_network_detail().contains("passed"));
            match flow {
                "edit" => ui.set_job_targets("10.0.0.77".into()),
                "profile load" => fill_settings(&ui, &profile.job),
                "repeat" => fill_settings(&ui, &repeat_job(&saved).unwrap()),
                _ => unreachable!(),
            }
            // These flows all use the same settings-edited -> production draft
            // handler as the actual text inputs, Load and Repeat callbacks.
            ui.invoke_settings_edited();
            assert!(!ui.get_network_detail().contains("passed"));
            assert!(!ui.get_job_valid());
            assert!(matches!(actions.borrow().last(), Some(Action::SetDraft(_))));
            assert!(
                ui.get_has_network_coverage(),
                "{flow} erased the selected scan's visible coverage"
            );
            let selected = cache
                .borrow()
                .clone()
                .expect("selected History coverage must remain exportable");
            assert_eq!(
                selected, original,
                "{flow} substituted draft settings for saved scan metadata"
            );
            let snapshot = rows.export_rows();
            assert_eq!(
                serde_json::to_value(&snapshot).unwrap(),
                serde_json::to_value(&expected_rows).unwrap()
            );
            let output = path.join("selected-report.json");
            studio_inspection::write_export_with_coverage(
                &output,
                &snapshot,
                Some(&selected),
                true,
            )
            .unwrap();
            let exported: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
            assert_eq!(exported["version"], 2);
            assert_eq!(
                exported["coverage"],
                serde_json::to_value(&original).unwrap()
            );
            assert_eq!(
                exported["rows"],
                serde_json::to_value(&expected_rows).unwrap()
            );
            let csv = studio_inspection::csv_with_coverage(&snapshot, Some(&selected)).unwrap();
            assert!(csv.contains("\r\nscan_coverage,"));
            assert!(csv.contains("\r\nnot_scanned,"));
            assert_eq!(
                csv.lines()
                    .filter(|line| line.starts_with("result,"))
                    .count(),
                expected_rows.len()
            );
        }
    }
    drop(store);
    std::fs::remove_dir_all(path).unwrap();
}
