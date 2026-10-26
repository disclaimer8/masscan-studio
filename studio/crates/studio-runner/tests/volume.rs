use std::time::{Duration, Instant};
use studio_app::{Action, Controller, Update};
use studio_protocol::*;
#[test]
fn hundred_thousand_results_survive_a_display_polled_at_twenty_hz() {
    let dir = std::env::temp_dir().join(format!("studio-volume-{}", id_text(new_id().unwrap())));
    let mut app =
        Controller::open(dir.clone(), env!("CARGO_BIN_EXE_studio-runner").into()).unwrap();
    let mut job = Job::example(Backend::Simulation);
    job.targets = "198.18.0.2-198.18.0.11".into();
    job.ports = "1-10000".into();
    job.rate = 10000;
    app.send(Action::Start(job)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut rows = 0;
    let mut completed = false;
    while Instant::now() < deadline && !completed {
        for u in app.poll() {
            match u {
                Update::Rows(batch) => rows += batch.len(),
                Update::State(s, detail) => {
                    assert!(
                        !matches!(s, Status::Failed | Status::Interrupted),
                        "{detail}"
                    );
                    completed |= s == Status::Completed;
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(completed);
    assert_eq!(rows, 100000);
    drop(app);
    let db = studio_store::Store::open(&dir).unwrap();
    let scan = db.scans().unwrap().remove(0);
    assert_eq!(scan.status, Status::Completed);
    assert_eq!(db.rows(scan.scan).unwrap().len(), 100000);
    drop(db);
    std::fs::remove_dir_all(dir).unwrap();
}
