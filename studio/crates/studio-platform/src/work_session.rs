//! Operator-authorized macOS working-session protocol. No shell commands cross IPC.
use crate::{audit::Peer, unix::Identity};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;
pub const MAX_FRAME: usize = 16 * 1024;
pub const MAX_ACTIVE: usize = 8;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub uid: u32,
    pub pid: u32,
    pub tool_hash: String,
    pub runner_hash: String,
    pub caller_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Fixture {
    Up {},
    Down {},
    Status {},
    Supervise {
        case: String,
        driver: PathBuf,
        prior: Option<String>,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "request", deny_unknown_fields)]
pub enum Request {
    Status {},
    Stop {},
    Helper {
        hash: String,
        endpoint: PathBuf,
        owner: Identity,
    },
    Fixture {
        operation: Fixture,
    },
    Export {
        nonce: String,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "response", deny_unknown_fields)]
pub enum Response {
    Status { config: Config, active: usize },
    HelperStarted,
    Started {},
    Output { stderr: bool, bytes: Vec<u8> },
    Done { code: i32 },
    Error { message: String },
}
pub fn valid_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn validate_config(c: &Config) -> Result<()> {
    if c.uid == 0
        || c.pid == 0
        || [&c.tool_hash, &c.runner_hash, &c.caller_hash]
            .iter()
            .any(|h| !valid_hex(h, 64))
    {
        return Err("Invalid work-session identity or hashes".into());
    }
    Ok(())
}
pub fn validate_request(r: &Request, c: &Config, peer: &Identity) -> Result<()> {
    if peer.uid != c.uid || peer.uid == 0 {
        return Err("Work-session caller account differs".into());
    }
    match r {
        Request::Helper {
            hash,
            endpoint,
            owner,
        } => {
            if hash != &c.runner_hash
                || owner != peer
                || !endpoint.is_absolute()
                || endpoint.as_os_str().len() > 100
            {
                return Err("Helper hash, owner or endpoint differs".into());
            }
        }
        Request::Fixture {
            operation:
                Fixture::Supervise {
                    case,
                    driver,
                    prior,
                },
        } => {
            if ![
                "complete",
                "stop-preparing",
                "stop-running",
                "pause",
                "resume",
                "guard",
            ]
            .contains(&case.as_str())
                || !driver.is_absolute()
                || driver.as_os_str().len() > 4096
                || (case == "resume") != prior.is_some()
                || prior.as_ref().is_some_and(|n| !valid_hex(n, 32))
            {
                return Err("Invalid fixed fixture request".into());
            }
        }
        Request::Export { nonce } if !valid_hex(nonce, 32) => {
            return Err("Invalid evidence nonce".into());
        }
        _ => {}
    }
    Ok(())
}
pub fn directory(uid: u32) -> PathBuf {
    PathBuf::from(format!(
        "/Library/PrivilegedHelperTools/MasscanStudio/work-{uid}"
    ))
}
/// Root-owned immutable namespace; also rejects ACLs and symlink ancestors.
pub fn protected(path: &Path, socket: bool) -> Result<()> {
    if fs::canonicalize(path).map_err(|e| e.to_string())? != path {
        return Err("Work-session path is not canonical".into());
    }
    for (i, p) in path.ancestors().enumerate() {
        crate::macos::reject_extended_acl(p)?;
        let m = fs::symlink_metadata(p).map_err(|e| e.to_string())?;
        let kind = if i == 0 {
            if socket {
                m.file_type().is_socket()
            } else {
                m.is_file() || m.is_dir()
            }
        } else {
            m.is_dir()
        };
        if m.uid() != 0 || !kind || (!(socket && i == 0) && m.mode() & 0o022 != 0) {
            return Err("Untrusted work-session path owner/type/mode".into());
        }
    }
    Ok(())
}
fn transfer(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    let mut n = 0;
    while n < bytes.len() {
        if cancelled.load(Ordering::Acquire) {
            return Err("Work-session request cancelled".into());
        }
        if Instant::now() >= deadline {
            return Err("Work-session request deadline".into());
        }
        match stream.read(&mut bytes[n..]) {
            Ok(0) => return Err("Work-session connection closed".into()),
            Ok(count) => n += count,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
pub fn read<T: DeserializeOwned>(
    stream: &mut UnixStream,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<T> {
    stream.set_nonblocking(true).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    let mut header = [0; 4];
    transfer(stream, &mut header, deadline, cancelled)?;
    let n = u32::from_be_bytes(header) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err("Work-session frame exceeds bound".into());
    }
    let mut bytes = vec![0; n];
    transfer(stream, &mut bytes, deadline, cancelled)?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
pub fn write<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    write_until(stream, value, Instant::now() + Duration::from_secs(2))
}
pub fn write_until<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("Work-session frame exceeds bound".into());
    }
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&bytes);
    stream
        .set_write_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| e.to_string())?;
    let mut sent = 0;
    while sent < frame.len() {
        if Instant::now() >= deadline {
            return Err("Work-session write deadline".into());
        }
        match stream.write(&frame[sent..]) {
            Ok(0) => return Err("Work-session connection closed".into()),
            Ok(n) => sent += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

pub fn connect() -> Result<Option<(UnixStream, Config)>> {
    let owner = Identity::current()?;
    let dir = directory(owner.uid);
    match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    protected(&dir, false)?;
    let file = dir.join("host.json");
    protected(&file, false)?;
    if fs::metadata(&file).map_err(|e| e.to_string())?.len() > MAX_FRAME as u64 {
        return Err("Oversized work-session metadata".into());
    }
    let c: Config = serde_json::from_slice(&fs::read(file).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    validate_config(&c)?;
    if c.uid != owner.uid {
        return Err("Work-session owner differs".into());
    }
    let path = dir.join("socket");
    protected(&path, true)?;
    let stream = UnixStream::connect(path).map_err(|e| format!("Work session unavailable: {e}"))?;
    let peer = Peer::from_stream(&stream)?;
    let exe = crate::macos::installed_path(&c.tool_hash)?;
    if peer.uid != 0 || peer.pid != c.pid || peer.executable != exe {
        return Err("Unexpected work-session host identity".into());
    }
    crate::trusted::verify(&exe, &c.tool_hash)?;
    peer.verify(&stream)?;
    Ok(Some((stream, c)))
}
pub struct Lease {
    stream: UnixStream,
}
impl Lease {
    pub fn check(&mut self) -> Result<()> {
        let mut b = [0];
        match self.stream.read(&mut b) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            _ => Err("Work-session helper lease ended".into()),
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}
pub struct Watch {
    stop: std::sync::Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Lease {
    pub fn watch(mut self, direct: &UnixStream) -> Result<Watch> {
        let direct = direct.try_clone().map_err(|e| e.to_string())?;
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                if self.check().is_err() {
                    let _ = direct.shutdown(std::net::Shutdown::Both);
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        Ok(Watch {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub fn helper(
    path: &Path,
    hash: &str,
    endpoint: &Path,
    owner: &Identity,
    cancelled: &AtomicBool,
) -> Result<Option<Lease>> {
    let Some((mut stream, c)) = connect()? else {
        return Ok(None);
    };
    if path != crate::macos::installed_path(&c.runner_hash)? || hash != c.runner_hash {
        return Err("Work session authorizes a different helper build".into());
    }
    write(
        &mut stream,
        &Request::Helper {
            hash: hash.into(),
            endpoint: endpoint.into(),
            owner: owner.clone(),
        },
    )?;
    match read(&mut stream, Duration::from_secs(5), cancelled)? {
        Response::HelperStarted => {
            stream.set_nonblocking(true).map_err(|e| e.to_string())?;
            Ok(Some(Lease { stream }))
        }
        Response::Error { message } => Err(message),
        _ => Err("Unexpected work-session helper reply".into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Config, Identity) {
        (
            Config {
                uid: 501,
                pid: 1,
                tool_hash: "a".repeat(64),
                runner_hash: "b".repeat(64),
                caller_hash: "a".repeat(64),
            },
            Identity {
                uid: 501,
                pid: 22,
                birth: [1, 2],
                executable: "/approved/tool".into(),
            },
        )
    }
    #[test]
    fn refuses_wrong_owner_hash_and_arbitrary_fixture_requests() {
        let (c, p) = fixture();
        let mut other = p.clone();
        other.birth[0] += 1;
        assert!(
            validate_request(
                &Request::Helper {
                    hash: c.runner_hash.clone(),
                    endpoint: "/tmp/socket".into(),
                    owner: other
                },
                &c,
                &p
            )
            .is_err()
        );
        assert!(
            validate_request(
                &Request::Helper {
                    hash: "c".repeat(64),
                    endpoint: "/tmp/socket".into(),
                    owner: p.clone()
                },
                &c,
                &p
            )
            .is_err()
        );
        for case in ["shell", "up; rm", "resume"] {
            assert!(
                validate_request(
                    &Request::Fixture {
                        operation: Fixture::Supervise {
                            case: case.into(),
                            driver: "/tmp/history".into(),
                            prior: None
                        }
                    },
                    &c,
                    &p
                )
                .is_err()
            );
        }
        assert!(
            validate_request(
                &Request::Export {
                    nonce: "../../etc".into()
                },
                &c,
                &p
            )
            .is_err()
        );
        other = p.clone();
        other.uid = 502;
        assert!(validate_request(&Request::Status {}, &c, &other).is_err());
    }
    #[test]
    fn framing_refuses_oversize_unknown_fields_and_partial_deadlines() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
            .unwrap();
        assert!(
            read::<Request>(&mut b, Duration::from_millis(100), &AtomicBool::new(false)).is_err()
        );
        assert!(serde_json::from_str::<Request>(r#"{"request":"Stop","shell":"id"}"#).is_err());
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&[0]).unwrap();
        let begin = Instant::now();
        assert!(
            read::<Request>(&mut b, Duration::from_millis(100), &AtomicBool::new(false)).is_err()
        );
        assert!(begin.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn leases_are_independent_and_detect_host_disconnect() {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let mut lease = Lease { stream: a };
        assert!(lease.check().is_ok());
        drop(b);
        assert!(lease.check().is_err());
        let (a, b) = UnixStream::pair().unwrap();
        drop(Lease { stream: a });
        let mut b = b;
        assert_eq!(b.read(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn host_loss_closes_direct_helper_ipc_but_normal_watch_drop_does_not() {
        let (control, host) = UnixStream::pair().unwrap();
        control.set_nonblocking(true).unwrap();
        let (direct, mut runner) = UnixStream::pair().unwrap();
        runner
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let watch = Lease { stream: control }.watch(&direct).unwrap();
        drop(host);
        assert_eq!(runner.read(&mut [0]).unwrap(), 0);
        drop(watch);
        let (control, mut host) = UnixStream::pair().unwrap();
        control.set_nonblocking(true).unwrap();
        let (direct, mut runner) = UnixStream::pair().unwrap();
        runner
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        drop(Lease { stream: control }.watch(&direct).unwrap());
        assert_eq!(host.read(&mut [0]).unwrap(), 0);
        assert!(runner.read(&mut [0]).is_err());
    }
}
