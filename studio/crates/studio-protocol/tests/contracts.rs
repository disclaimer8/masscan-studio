use std::io::Cursor;
use studio_protocol::*;

#[test]
fn framing_rejects_oversize_truncation_and_old_version() {
    assert!(read_frame::<Command>(&mut Cursor::new((MAX_FRAME as u32 + 1).to_be_bytes())).is_err());
    assert!(read_frame::<Command>(&mut Cursor::new([0, 0, 0, 9, 1, 2])).is_err());
    let mut bytes = Vec::new();
    let mut e = Envelope::new([1; 16], [2; 16], [3; 16], 1, Command::Stop);
    write_frame(&mut bytes, &e).unwrap();
    assert_eq!(
        read_frame::<Command>(&mut Cursor::new(bytes))
            .unwrap()
            .payload,
        Command::Stop
    );
    e.version = 0;
    let mut guard = ReceiveOrder::new([1; 16], [2; 16], [3; 16]);
    assert!(guard.accept(&e).is_err());
}

#[test]
fn wrong_attempt_and_duplicate_sequence_never_advance_state() {
    let mut g = ReceiveOrder::new([1; 16], [2; 16], [3; 16]);
    let foreign = Envelope::new([1; 16], [2; 16], [9; 16], 1, Command::Stop);
    assert!(g.accept(&foreign).is_err());
    let right = Envelope::new([1; 16], [2; 16], [3; 16], 1, Command::Stop);
    g.accept(&right).unwrap();
    assert!(g.accept(&right).is_err());
}

#[test]
fn exact_seed_and_lab_boundary() {
    let mut j = Job::example(Backend::Simulation);
    j.seed = "18446744073709551614".into();
    assert!(j.prepare().is_ok());
    j.backend = Backend::MacFeth;
    j.targets = "192.168.1.1".into();
    assert!(j.prepare().is_err());
    j.targets = "198.18.0.2".into();
    j.seed = "01".into();
    assert!(j.prepare().is_err());
}
