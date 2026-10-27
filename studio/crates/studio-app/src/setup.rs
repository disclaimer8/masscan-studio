//! Setup state is owned by the controller worker; no elevation at startup.
use crate::*;
use std::path::Path;
#[derive(Default)]
pub(super) struct Setup {
    prepared: Option<studio_platform::setup::Prepared>,
}
impl Setup {
    pub fn perform(
        &mut self,
        install: bool,
        source: &Path,
        blocked: bool,
        cancelled: &AtomicBool,
    ) -> Update {
        let result = (|| -> Result<(bool, String), String> {
            if blocked {
                return Err("Stop the scan and Lock the authorized session before setup.".into());
            }
            if !install {
                self.prepared = None;
                self.prepared = Some(studio_platform::setup::Prepared::new(source, cancelled)?);
            }
            let p = self
                .prepared
                .as_ref()
                .ok_or("Check setup before installing the scanner helper.")?;
            if install {
                p.install(cancelled)?;
            }
            let ready = p.installed()?;
            Ok((
                ready,
                if ready {
                    "The scanner helper for this build is installed and verified. Close setup, then Authorize when you need a scanning session. No scan has started.".into()
                } else {
                    "This build needs its scanner helper installed. Install will ask for administrator permission. Simulation works without it.".into()
                },
            ))
        })();
        match result {
            Ok((ready, detail)) => Update::Setup {
                busy: false,
                ready,
                installable: !ready,
                detail,
            },
            Err(detail) => {
                self.prepared = None;
                Update::Setup {
                    busy: false,
                    ready: false,
                    installable: false,
                    detail,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn detail(u: Update) -> String {
        match u {
            Update::Setup {
                busy,
                ready,
                installable,
                detail,
            } => {
                assert!(!busy && !ready && !installable);
                detail
            }
            _ => panic!("Expected setup result"),
        }
    }
    #[test]
    fn install_requires_a_successful_check() {
        let u =
            Setup::default().perform(true, Path::new("/missing"), false, &AtomicBool::new(false));
        assert!(detail(u).contains("Check"));
    }
    #[test]
    fn setup_refuses_active_or_authorized_session_before_io() {
        for install in [false, true] {
            let u = Setup::default().perform(
                install,
                Path::new("/missing"),
                true,
                &AtomicBool::new(false),
            );
            assert!(detail(u).contains("Lock"));
        }
    }
    #[test]
    fn missing_source_never_reports_ready_or_installable() {
        let u = Setup::default().perform(
            false,
            Path::new("/missing/studio-runner"),
            false,
            &AtomicBool::new(false),
        );
        assert!(detail(u).contains("bundled"));
    }
    #[test]
    fn setup_command_gate_prevents_late_authorization_and_allows_cancel() {
        let (tx, rx) = mpsc::sync_channel(8);
        let (_out, updates) = mpsc::sync_channel(8);
        let c = Controller {
            commands: tx,
            updates,
            stop: Arc::new(AtomicBool::new(false)),
            cancel_auth: Arc::new(AtomicBool::new(false)),
            setup_pending: Arc::new(AtomicBool::new(false)),
            cancel_setup: Arc::new(AtomicBool::new(false)),
            error: Arc::new(Mutex::new(None)),
            worker: None,
        };
        c.send(Action::CheckSetup).unwrap();
        assert!(c.send(Action::Authorize).is_err());
        assert!(c.send(Action::InstallRunner).is_err());
        c.send(Action::CancelSetup).unwrap();
        assert!(c.cancel_setup.load(Ordering::Acquire));
        assert!(matches!(rx.try_recv().unwrap(), Action::CheckSetup));
        assert!(
            rx.try_recv().is_err(),
            "cancel must bypass the pending command"
        );
        c.setup_pending.store(false, Ordering::Release);
        c.send(Action::Authorize).unwrap();
    }
}
