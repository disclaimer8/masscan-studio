//! Windows/Npcap: TX/RX половины адаптера поверх владеемых [`PcapHandle`].
//! Весь код здесь безопасный; указатели pcap не покидают `handle`.
//!
//! # Контракт
//! * Два НЕЗАВИСИМЫХ handle на одно устройство: TX (только `pcap_sendpacket`) и
//!   RX (только чтение). Каждый принадлежит одному потоку движка.
//! * RX явно nonblocking. Один вызов `recv` ждёт кадр до АБСОЛЮТНОГО дедлайна
//!   `min(timeout, 50 мс, IO_BUDGET = 42 мс)`: 42 мс это решение контролёра по
//!   спайку (запас не менее 7.2 мс над худшим измеренным срывом планировщика);
//!   контракт 50 мс не повышается. Мусор (свои кадры, усечённые кадры)
//!   дедлайн не продлевает. Кадр копируется в буфер вызывающего внутри
//!   `PcapHandle::poll_into` до любого следующего вызова pcap.
//! * TX синхронный и НЕ отменяемый: `pcap_sendpacket` rc 0 → `Sent`, любой
//!   другой rc → `Uncertain` (исход неизвестен, повтора нет, checkpoint
//!   запрещён). `WouldBlockUnsent` НЕ выдаётся никогда: драйвер не сообщает
//!   «точно не отправлено», а выводить его из текста `pcap_geterr` запрещено.
//!   rc 0 не доказывает доставку (кадр мог уйти в пустоту при потере линка).
//!   Ошибки проверки ДО отправки (длина кадра) это `IoError`.
//! * Свои TX-кадры: Npcap показывает RX-handle собственные отправленные кадры.
//!   Они отсекаются в драйвере фильтром `not ether src <source_mac>` и,
//!   независимо, программно по MAC источника ДО разбора. Фильтр режет только
//!   кадры с НАШИМ source MAC, поэтому SYN-ACK/RST пира (его MAC) проходят.
//!   Из-за этого `source_mac` обязан отличаться от `next_hop_mac`.
//! * TX handle не копит захваченные кадры: фильтр `ret #0` отбрасывает всё в
//!   драйвере (иначе непрочитанный TX handle заполняет буфер и теряет кадры),
//!   плюс минимальные snaplen и буфер.
//! * Режим promiscuous НЕ включается: ответы приходят на MAC самого NIC. Если
//!   `source_mac` в binding задан отличным от MAC адаптера, ответы без
//!   promiscuous до RX не дойдут (ограничение, а не скрытая настройка).
//! * Health: `ps_drop` RX handle (кумулятивно, чтение не сбрасывает, `u32`
//!   оборачивается) через [`DropCounter`]; ошибка `pcap_stats` это `Err`, а не
//!   `Some(0)`. Область: потери в очереди NPF (паритет с `PACKET_STATISTICS`
//!   Linux). Потери ниже NPF (кольцо драйвера NIC, гипервизор) не видны ни
//!   `ps_drop`, ни `ps_ifdrop` (на Npcap он всегда 0): задокументированное
//!   ограничение.

use std::sync::Arc;
use std::sync::atomic::Ordering::{Relaxed, Release};
use std::time::{Duration, Instant};

use rmasscan_core::packet::LinkType;
use rmasscan_core::probe::AdapterBinding;
use rmasscan_engine::{AdapterPair, IoError, MAX_IO_TIMEOUT, Rx, RxHealth, SendStatus, Tx};

use super::handle::{DropCounter, OpenParams, PcapHandle, Polled, resolve_device};
use super::loader::NpcapApi;
use crate::{Counters, NetError, NetStatsHandle, OpenedAdapter};

/// Внутренний бюджет одного вызова адаптера (решение контролёра по спайку).
pub(crate) const IO_BUDGET: Duration = Duration::from_millis(42);
/// Ethernet-заголовок без полезной нагрузки.
pub(crate) const MIN_TX_FRAME: usize = 14;
/// Максимум кадра на отправку (MTU 1500 + заголовок + VLAN). SYN-пробы много меньше.
pub(crate) const MAX_TX_FRAME: usize = 1518;

const RX_SNAPLEN: i32 = 2048;
const RX_BUFFER_BYTES: i32 = 4 << 20;
const TX_SNAPLEN: i32 = 64;
const TX_BUFFER_BYTES: i32 = 65_536;
/// До этого остатка спим по 1 мс, затем отдаём квант (`yield_now`): так
/// измерен спайк (Hybrid), без активного кручения на всём дедлайне.
const SPIN_BELOW: Duration = Duration::from_millis(3);

fn closed_error() -> IoError {
    IoError::new("adapter closed after an earlier fatal error")
}

fn publish_drops(counters: &Counters, total: u64) {
    counters.kernel_drops.store(total, Relaxed);
    counters.kernel_drops_known.store(true, Release);
}

/// TX-половина.
pub(crate) struct TxHalf {
    handle: PcapHandle,
    counters: Arc<Counters>,
}

impl TxHalf {
    pub(crate) fn new(handle: PcapHandle, counters: Arc<Counters>) -> Self {
        Self { handle, counters }
    }
}

impl Tx for TxHalf {
    fn send(&mut self, frame: &[u8], _timeout: Duration) -> Result<SendStatus, IoError> {
        // Проверка ДО вызова драйвера: кадр не уходит, исход известен.
        if !(MIN_TX_FRAME..=MAX_TX_FRAME).contains(&frame.len()) {
            Counters::bump(&self.counters.tx_errors);
            return Err(IoError::new(format!(
                "frame length {} is outside {MIN_TX_FRAME}..={MAX_TX_FRAME}; nothing was sent",
                frame.len()
            )));
        }
        // Ровно один синхронный вызов, без повторов; `timeout` не применим:
        // pcap_sendpacket нельзя отменить (граница измерена в спайке).
        if self.handle.send_raw(frame) == 0 {
            Counters::bump(&self.counters.tx_sent);
            Ok(SendStatus::Sent)
        } else {
            Counters::bump(&self.counters.tx_uncertain);
            Ok(SendStatus::Uncertain)
        }
    }
}

/// RX-половина.
pub(crate) struct RxHalf {
    handle: Option<PcapHandle>,
    own_mac: [u8; 6],
    counters: Arc<Counters>,
    drops: DropCounter,
}

impl RxHalf {
    pub(crate) fn new(
        handle: PcapHandle,
        own_mac: [u8; 6],
        counters: Arc<Counters>,
        baseline_drop: u32,
    ) -> Self {
        Self {
            handle: Some(handle),
            own_mac,
            counters,
            drops: DropCounter::new(baseline_drop),
        }
    }

    /// Пауза до следующего опроса: сон 1 мс, пока остаток больше порога.
    fn wait(deadline: Instant) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left > SPIN_BELOW {
            std::thread::sleep(Duration::from_millis(1));
        } else {
            std::thread::yield_now();
        }
    }

    /// Фатальная ошибка: итог потерь фиксируется, handle закрывается.
    fn fatal(&mut self, msg: String) -> IoError {
        Counters::bump(&self.counters.rx_errors);
        self.flush_drops();
        self.handle = None;
        IoError::new(msg)
    }

    /// Фоновое обновление снимка; ошибку не скрывает навсегда (достоверность
    /// проверяет `health`, который возвращает её вызывающему).
    fn flush_drops(&mut self) {
        if let Some(h) = self.handle.as_mut()
            && let Ok(st) = h.stats_raw()
        {
            publish_drops(&self.counters, self.drops.update(st.ps_drop));
        }
    }
}

impl Rx for RxHalf {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError> {
        let deadline = Instant::now() + timeout.min(MAX_IO_TIMEOUT).min(IO_BUDGET);
        loop {
            let Some(h) = self.handle.as_mut() else {
                return Err(closed_error());
            };
            match h.poll_into(buffer) {
                Polled::Frame(n) => {
                    // Свой кадр отсекается ДО дорогого разбора движком.
                    if n >= 12 && buffer[6..12] == self.own_mac {
                        Counters::bump(&self.counters.rx_outgoing);
                    } else {
                        Counters::bump(&self.counters.rx_packets);
                        return Ok(Some(n));
                    }
                }
                Polled::Truncated => Counters::bump(&self.counters.rx_truncated),
                Polled::Empty => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    Self::wait(deadline);
                    continue;
                }
                Polled::Error(rc) => {
                    let text = h.last_error();
                    return Err(self.fatal(format!("pcap_next_ex failed (code {rc}): {text}")));
                }
                Polled::Eof => {
                    return Err(self.fatal("pcap_next_ex reported EOF on a live capture".into()));
                }
                Polled::Malformed(why) => return Err(self.fatal(why.into())),
            }
            // Мусор не продлевает вызов.
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    fn health(&mut self, _timeout: Duration) -> Result<RxHealth, IoError> {
        let Some(h) = self.handle.as_mut() else {
            return Err(closed_error());
        };
        // Один быстрый вызов (спайк: не более 1.3 мс). Ошибка это Err.
        match h.stats_raw() {
            Ok(st) => {
                let total = self.drops.update(st.ps_drop);
                publish_drops(&self.counters, total);
                Ok(RxHealth {
                    kernel_drops: Some(total),
                })
            }
            Err(rc) => Err(IoError::new(format!(
                "pcap_stats failed (code {rc}): {}",
                h.last_error()
            ))),
        }
    }
}

impl Drop for RxHalf {
    fn drop(&mut self) {
        // Итог остаётся в общих счётчиках после закрытия handle.
        self.flush_drops();
    }
}

/// Проверка binding без обращения к Npcap.
pub(crate) fn check_binding(binding: &AdapterBinding) -> Result<(), NetError> {
    if binding.link_type != LinkType::Ethernet {
        return Err(NetError::UnsupportedLink(format!(
            "{:?} (Windows Npcap adapter supports Ethernet only)",
            binding.link_type
        )));
    }
    let mac = binding.source_mac;
    if mac == [0; 6] || mac[0] & 1 == 1 {
        return Err(NetError::InterfaceMismatch(format!(
            "source MAC {} is not a unicast address",
            mac_text(&mac)
        )));
    }
    if mac == binding.next_hop_mac {
        return Err(NetError::InterfaceMismatch(
            "source MAC equals the next-hop MAC: own transmitted frames could not be told \
             from replies"
                .into(),
        ));
    }
    Ok(())
}

pub(crate) fn mac_text(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Открывает пару TX/RX на `api`. При любой ошибке уже открытые handle
/// закрываются (Drop) раньше, чем отпускается библиотека.
pub(crate) fn open_with(
    api: &Arc<NpcapApi>,
    binding: &AdapterBinding,
) -> Result<OpenedAdapter, NetError> {
    check_binding(binding)?;
    let device = resolve_device(api, &binding.interface_id)?;

    let mut tx = PcapHandle::open_ethernet(
        api,
        &device,
        OpenParams {
            snaplen: TX_SNAPLEN,
            promisc: false,
            timeout_ms: 1,
            immediate: true,
            buffer_bytes: TX_BUFFER_BYTES,
        },
    )?;
    tx.set_drop_all_filter()?;

    let mut rx = PcapHandle::open_ethernet(
        api,
        &device,
        OpenParams {
            snaplen: RX_SNAPLEN,
            promisc: false,
            timeout_ms: 1,
            immediate: true,
            buffer_bytes: RX_BUFFER_BYTES,
        },
    )?;
    rx.set_nonblock(true)?;
    if rx.get_nonblock() != 1 {
        return Err(NetError::System(
            "pcap_setnonblock did not take effect on the RX handle".into(),
        ));
    }
    let expr = format!("not ether src {}", mac_text(&binding.source_mac));
    let mut filter = rx.compile(&expr)?;
    rx.set_filter(&mut filter)?;
    drop(filter); // библиотека скопировала программу
    // Базовое значение попытки: handle новый, но берём измерение, а не 0.
    let baseline = rx.stats_raw().map_err(|rc| {
        NetError::System(format!(
            "pcap_stats failed on the new RX handle (code {rc}): {}",
            rx.last_error()
        ))
    })?;

    let counters = Arc::new(Counters::default());
    Ok(OpenedAdapter {
        io: AdapterPair {
            tx: Box::new(TxHalf::new(tx, Arc::clone(&counters))),
            rx: Box::new(RxHalf::new(
                rx,
                binding.source_mac,
                Arc::clone(&counters),
                baseline.ps_drop,
            )),
        },
        stats: NetStatsHandle::new(counters),
    })
}

/// Открывает адаптер на настоящем Npcap.
#[cfg(windows)]
pub(crate) fn open(binding: &AdapterBinding) -> Result<OpenedAdapter, NetError> {
    check_binding(binding)?;
    let api = NpcapApi::load()?;
    open_with(&api, binding)
}
