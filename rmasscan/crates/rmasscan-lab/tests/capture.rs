use rmasscan_lab::capture::classify;
#[test]
fn queued_outgoing_tail_does_not_pass_as_complete_capture() {
    let meta = serde_json::json!({"marker_acked":true,"drops":0,"truncated_frames":0,"rx_counter_mismatch":false,"frames_in":1,"frames_out":1,"kernel_tp_packets":3});
    assert!(!rmasscan_lab::capture::capture_valid(&meta));
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
