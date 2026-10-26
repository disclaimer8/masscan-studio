use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use studio_app::{Action, Controller, Update};
use studio_protocol::{Backend, Id, Job};
fn wait(app: &mut Controller, expected: bool) -> Option<Id> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut selected = None;
    while Instant::now() < deadline {
        for update in app.poll() {
            match update {
                Update::Profiles(_, id) => selected = id,
                Update::ProfileResult(result) => {
                    assert_eq!(result.is_ok(), expected, "{result:?}");
                    return selected;
                }
                Update::Authorization { .. } | Update::State(..) => {
                    panic!("profile operation touched scanner/authorization")
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("profile result timeout");
}
#[test]
fn profile_operations_do_not_start_runner_or_create_scans() {
    let root = std::env::temp_dir().join(format!(
        "studio-profile-controller-{}",
        studio_protocol::id_text(studio_protocol::new_id().unwrap())
    ));
    let mut app = Controller::open(
        root.clone(),
        PathBuf::from("missing-runner-must-not-be-started"),
    )
    .unwrap();
    let mut job = Job::example(Backend::Simulation);
    job.seed = u64::MAX.to_string();
    app.send(Action::SaveProfile {
        id: None,
        name: "Office".into(),
        job: job.clone(),
    })
    .unwrap();
    let id = wait(&mut app, true).unwrap();
    app.send(Action::SaveProfile {
        id: None,
        name: "office".into(),
        job: job.clone(),
    })
    .unwrap();
    wait(&mut app, false);
    job.ports = "80,443".into();
    app.send(Action::SaveProfile {
        id: Some(id),
        name: "Changed".into(),
        job: job.clone(),
    })
    .unwrap();
    wait(&mut app, true);
    drop(app);
    let db = studio_store::Store::open(&root).unwrap();
    assert!(db.scans().unwrap().is_empty());
    assert_eq!(db.profiles().unwrap()[0].job, job);
    drop(db);
    let mut app = Controller::open(root.clone(), PathBuf::from("missing-runner")).unwrap();
    app.send(Action::DeleteProfile(id)).unwrap();
    wait(&mut app, true);
    drop(app);
    let db = studio_store::Store::open(&root).unwrap();
    assert!(db.scans().unwrap().is_empty());
    assert!(db.profiles().unwrap().is_empty());
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}
