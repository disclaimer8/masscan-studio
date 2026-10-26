#![cfg(any(target_os = "macos", target_os = "linux"))]
use std::{os::unix::net::UnixStream, time::Duration};
use studio_platform::unix::{Endpoint, Identity, peer_identity};

#[test]
fn private_endpoint_checks_live_peer_and_process_birth() {
    let me = Identity::current().unwrap();
    let endpoint = Endpoint::create().unwrap();
    let client = UnixStream::connect(endpoint.path()).unwrap();
    let server = endpoint.accept(Duration::from_secs(1), &me).unwrap();
    assert_eq!(peer_identity(&client).unwrap(), me);
    assert_eq!(peer_identity(&server).unwrap(), me);
    let mut stale = me.clone();
    stale.birth[0] ^= 1;
    assert!(
        stale.verify(&server).is_err(),
        "reused PID with a different birth is not this session"
    );
    let mut foreign = me.clone();
    foreign.uid ^= 1;
    assert!(foreign.verify(&server).is_err());
    let old_path = endpoint.path().to_owned();
    drop(server);
    drop(client);
    drop(endpoint);
    assert!(
        UnixStream::connect(old_path).is_err(),
        "closed endpoint cannot be reused"
    );
}

#[test]
fn world_accessible_endpoint_and_symlink_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let endpoint = Endpoint::create().unwrap();
    let me = Identity::current().unwrap();
    let parent = endpoint.path().parent().unwrap();
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Endpoint::connect(endpoint.path(), &me).is_err());
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let alias = parent.join("alias");
    symlink(endpoint.path(), &alias).unwrap();
    assert!(Endpoint::connect(&alias, &me).is_err());
    std::fs::remove_file(alias).unwrap();
}
