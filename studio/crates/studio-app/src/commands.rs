//! Bounded controller commands. Consecutive edits share one queued draft;
//! explicit actions seal that draft so later edits cannot overtake them.
use crate::Action;
use std::sync::{Arc, Mutex, Weak, mpsc};
use studio_protocol::Job;

struct Draft {
    value: Mutex<Option<(Job, u64)>>,
}
enum Message {
    Action(Action, u64),
    Draft(Arc<Draft>),
}
pub(crate) struct Sender {
    tx: mpsc::SyncSender<Message>,
    pending: Mutex<Weak<Draft>>,
}
pub(crate) struct Receiver(mpsc::Receiver<Message>);

pub(crate) fn channel(capacity: usize) -> (Sender, Receiver) {
    let (tx, rx) = mpsc::sync_channel(capacity);
    (
        Sender {
            tx,
            pending: Mutex::new(Weak::new()),
        },
        Receiver(rx),
    )
}
impl Sender {
    pub fn try_send(&self, (action, epoch): (Action, u64)) -> Result<(), ()> {
        let mut pending = self.pending.lock().unwrap();
        if let Action::SetDraft(job) = action {
            if let Some(draft) = pending.upgrade() {
                let mut value = draft.value.lock().unwrap();
                if value.is_some() {
                    *value = Some((job, epoch));
                    return Ok(());
                }
            }
            let draft = Arc::new(Draft {
                value: Mutex::new(Some((job, epoch))),
            });
            // A weak pointer neither retains consumed jobs nor hides receiver death.
            *pending = Arc::downgrade(&draft);
            self.tx.try_send(Message::Draft(draft)).map_err(|_| ())
        } else {
            *pending = Weak::new();
            self.tx
                .try_send(Message::Action(action, epoch))
                .map_err(|_| ())
        }
    }
}
impl Receiver {
    pub fn try_recv(&self) -> Result<(Action, u64), mpsc::TryRecvError> {
        Ok(match self.0.try_recv()? {
            Message::Action(action, epoch) => (action, epoch),
            Message::Draft(draft) => {
                // Mark consumed under the same lock used by edits. A racing edit
                // must enqueue a new message instead of changing an already read job.
                let (job, epoch) = draft.value.lock().unwrap().take().unwrap();
                (Action::SetDraft(job), epoch)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use studio_protocol::Backend;

    fn job(seed: &str) -> Job {
        Job {
            seed: seed.into(),
            ..Job::example(Backend::Simulation)
        }
    }

    #[test]
    fn edits_cannot_cross_a_network_check() {
        let (tx, rx) = channel(8);
        tx.try_send((Action::SetDraft(job("1")), 0)).unwrap();
        tx.try_send((Action::SetDraft(job("2")), 0)).unwrap();
        tx.try_send((Action::CheckNetwork(job("2")), 0)).unwrap();
        tx.try_send((Action::SetDraft(job("3")), 0)).unwrap();
        tx.try_send((Action::SetDraft(job("4")), 0)).unwrap();
        assert!(matches!(rx.try_recv().unwrap().0, Action::SetDraft(j) if j.seed == "2"));
        assert!(matches!(rx.try_recv().unwrap().0, Action::CheckNetwork(j) if j.seed == "2"));
        assert!(matches!(rx.try_recv().unwrap().0, Action::SetDraft(j) if j.seed == "4"));
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn edits_after_consumption_are_delivered_again() {
        let (tx, rx) = channel(8);
        tx.try_send((Action::SetDraft(job("1")), 0)).unwrap();
        assert!(matches!(rx.try_recv().unwrap().0, Action::SetDraft(j) if j.seed == "1"));
        tx.try_send((Action::SetDraft(job("2")), 1)).unwrap();
        let (a, epoch) = rx.try_recv().unwrap();
        assert!(matches!(a, Action::SetDraft(j) if j.seed == "2"));
        assert_eq!(epoch, 1);
    }

    #[test]
    fn explicit_commands_remain_bounded_and_keep_their_order() {
        let (tx, rx) = channel(2);
        tx.try_send((Action::Pause, 0)).unwrap();
        tx.try_send((Action::Resume, 0)).unwrap();
        assert!(tx.try_send((Action::Stop, 1)).is_err());
        assert!(tx.try_send((Action::SetDraft(job("1")), 1)).is_err());
        assert!(matches!(rx.try_recv().unwrap().0, Action::Pause));
        tx.try_send((Action::SetDraft(job("2")), 1)).unwrap();
        assert!(matches!(rx.try_recv().unwrap().0, Action::Resume));
        assert!(matches!(rx.try_recv().unwrap().0, Action::SetDraft(j) if j.seed == "2"));
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn receiver_death_is_not_hidden_by_a_pending_draft() {
        let (tx, rx) = channel(8);
        tx.try_send((Action::SetDraft(job("1")), 0)).unwrap();
        drop(rx);
        assert!(tx.try_send((Action::SetDraft(job("2")), 0)).is_err());
        assert!(tx.try_send((Action::Stop, 1)).is_err());
    }
}
