use rmasscan_lab::capture::classify;
#[test]
fn a_queued_outgoing_tail_missing_from_the_pcap_does_not_pass_as_complete_capture() {
    // The interface counted 3 frames (window 3..3) but the pcap holds 2 and tcpdump retired 2:
    // the last frame was queued and never written.
    let facts = rmasscan_lab::dump::Facts {
        start_markers: 1,
        end_markers: 3,
        quiesced: true,
        captured: Some(2),
        received: Some(2),
        dropped_kernel: Some(0),
        dropped_if: Some(0),
        interface_drop_delta: Some(0),
        pcap_frames: 2,
        pcap_error: None,
        tcpdump_exited: true,
        window_lo: Some(3),
        window_hi: Some(3),
    };
    assert!(!rmasscan_lab::dump::problems(&facts).is_empty());
}

#[test]
fn isolation_refuses_an_extra_link_or_default_route() {
    use serde_json::json;
    let links = json!([{"ifname":"lo"},{"ifname":"veth-a","linkinfo":{"info_kind":"veth"}}]);
    assert!(rmasscan_lab::capture::check_isolation_snapshot(&links, &json!([]), "0").is_ok());
    assert!(
        rmasscan_lab::capture::check_isolation_snapshot(&links, &json!([{"dst":"default"}]), "0")
            .is_err()
    );
    assert!(rmasscan_lab::capture::check_isolation_snapshot(&links, &json!([]), "1").is_err());
}
#[test]
fn truncated_ipv4_options_are_classified_without_indexing_past_end() {
    let mut frame = vec![0u8; 54];
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x4f;
    frame[23] = 6;
    let result = classify(&[(0., frame)], [1; 6], [2; 6]);
    assert_eq!(result["other"], 1);
}
