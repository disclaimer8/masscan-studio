//! Генерация probe: SYN-cookie, порт источника и кадр (AGPL-3.0). Порт
//! формулы `transmit_thread` (`src/main.c:371-402`) из masscan © Robert David
//! Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0). Формула
//! перенесена из CLI без изменения байтов; перестановка и индексы берутся из
//! [`crate::scan`] и [`crate::blackrock`], здесь они не переписаны.
//!
//! Два входа:
//! - [`ReadyPlan`] + [`ProbeCursor`]: runtime. Курсор отдаёт один и тот же
//!   probe, пока вызывающий не подтвердит отправку ([`ProbeCursor::advance_sent`]).
//!   План принимает только то, что runtime v1 умеет (shard 1/1, NIC 1,
//!   retries 0, rounds 14) и только новый запуск: продолжение идёт через
//!   checkpoint, не через `resume_index`/`resume_count`.
//! - [`for_each_probe`]: потоковый оракул для CLI (`--offline --packet-trace`),
//!   сохраняет все алгоритмы этапа 1 (retries, shard), с остановкой через
//!   [`ControlFlow`].

use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::sync::Arc;

use crate::blackrock::BlackRock;
use crate::config::{EffectiveConfig, Operation};
use crate::cookie::syn_cookie_ipv4;
use crate::packet::{LinkType, TcpSynTemplate};
use crate::scan::{ScanError, Shard, transmit_index_stream, transmit_scan_flow};

/// Раунды BlackRock, которые принимает runtime v1 (masscan по умолчанию).
pub const RUNTIME_BLACKROCK_ROUNDS: u32 = 14;

/// Ошибки плана и генерации probe.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("plan needs a scan configuration, got {0:?}")]
    NotScanOperation(Operation),
    #[error("legacy resume index {0} is not accepted for a new run (resume via checkpoint)")]
    ResumeIndexNotAllowed(u64),
    #[error("legacy resume count {0} is not accepted for a new run (resume via checkpoint)")]
    ResumeCountNotAllowed(u64),
    #[error("unsupported shard {one}/{of}: runtime v1 runs only shard 1/1")]
    UnsupportedShard { one: u32, of: u32 },
    #[error("unsupported retries {0}: runtime v1 runs only retries 0")]
    UnsupportedRetries(u32),
    #[error("unsupported blackrock rounds {0}: runtime v1 runs only {RUNTIME_BLACKROCK_ROUNDS}")]
    UnsupportedRounds(u32),
    #[error(
        "invalid source ports {first}-{last}: need 1 <= first <= last and a power-of-two width"
    )]
    InvalidSourcePorts { first: u16, last: u16 },
    #[error("target port {0} does not fit TCP (v1 is TCP only)")]
    PortNotTcp(u32),
    #[error("port {port_them}/{port_me} does not fit TCP (v1 is TCP only)")]
    PortDoesNotFit { port_them: u32, port_me: u32 },
    #[error("next index {next_index} is beyond the scan range {range}")]
    NextIndexBeyondRange { next_index: u64, range: u64 },
    #[error(transparent)]
    Scan(#[from] ScanError),
}

/// Разрешённые, неизменяемые параметры адаптера для генерации кадров.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterBinding {
    pub interface_id: String,
    pub link_type: LinkType,
    pub source_ipv4: u32,
    pub source_mac: [u8; 6],
    pub next_hop_mac: [u8; 6],
    /// `(first, last)` включительно; ширина должна быть степенью двойки.
    pub source_ports: (u16, u16),
}

/// Одна отправка SYN (main.c:371-402).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    /// Индекс цикла `i` (для runtime: порядковый номер probe).
    pub index: u64,
    pub ip_me: u32,
    pub port_me: u16,
    pub ip_them: u32,
    pub port_them: u16,
    pub seqno: u32,
    pub frame: Vec<u8>,
}

fn check_source_ports(first: u16, last: u16) -> Result<(), PlanError> {
    let width = u32::from(last)
        .wrapping_sub(u32::from(first))
        .wrapping_add(1);
    if first == 0 || first > last || !width.is_power_of_two() {
        return Err(PlanError::InvalidSourcePorts { first, last });
    }
    Ok(())
}

/// Формула источника и кадра (main.c:373-402).
#[derive(Debug, Clone)]
struct Builder {
    tmpl: TcpSynTemplate,
    ip_me0: u32,
    first: u16,
    port_mask: u32,
    entropy: u64,
}

impl Builder {
    fn new(binding: &AdapterBinding, seed: u64) -> Result<Builder, PlanError> {
        let (first, last) = binding.source_ports;
        check_source_ports(first, last)?;
        Ok(Builder {
            tmpl: TcpSynTemplate::new(binding.source_mac, binding.next_hop_mac, binding.link_type),
            ip_me0: binding.source_ipv4,
            first,
            // main.c:183-186: port_mask = last - first.
            port_mask: u32::from(last - first),
            entropy: seed,
        })
    }

    fn fill(
        &self,
        p: &mut Probe,
        i: u64,
        repeats: u64,
        xxx: u64,
        ip_them: u32,
        port_them: u32,
    ) -> Result<(), PlanError> {
        // ipv4_mask = 0, потому что адаптер даёт один адрес.
        let ipv4_mask = 0u32;
        let (ip_me, port_me) = if ipv4_mask != 0 || self.port_mask != 0 {
            let n = i.wrapping_add(repeats);
            // main.c:379-384.
            let ck = syn_cookie_ipv4(
                n as u32,
                (n >> 32) as u32,
                xxx as u32,
                (xxx >> 32) as u32,
                self.entropy,
            );
            (
                self.ip_me0.wrapping_add(((ck >> 16) as u32) & ipv4_mask),
                u32::from(self.first).wrapping_add(ck as u32 & self.port_mask),
            )
        } else {
            (self.ip_me0, u32::from(self.first))
        };
        let (Ok(port_them16), Ok(port_me16)) = (u16::try_from(port_them), u16::try_from(port_me))
        else {
            return Err(PlanError::PortDoesNotFit { port_them, port_me });
        };
        // main.c:389/:402: seqno = (unsigned)cookie.
        let seqno = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, self.entropy) as u32;
        self.tmpl
            .build_syn(ip_them, port_them16, ip_me, port_me16, seqno, &mut p.frame);
        p.index = i;
        p.ip_me = ip_me;
        p.port_me = port_me16;
        p.ip_them = ip_them;
        p.port_them = port_them16;
        p.seqno = seqno;
        Ok(())
    }
}

/// Поток probe этапа 1 без сети: те же индексы, что в C (`transmit_scan`),
/// SYN-cookie и порт источника как main.c:373-393. Сохраняет retries и shard
/// из `eff`. Резюме-поля `eff` применяются как в C.
///
/// Callback получает один переиспользуемый [`Probe`]. `Break(b)` останавливает
/// обход сразу и возвращается как `Ok(Break(b))`.
pub fn for_each_probe<B>(
    eff: &EffectiveConfig,
    binding: &AdapterBinding,
    mut f: impl FnMut(&Probe) -> ControlFlow<B>,
) -> Result<ControlFlow<B>, PlanError> {
    let builder = Builder::new(binding, eff.seed())?;
    let mut probe = Probe::default();
    let flow = transmit_scan_flow(
        eff.massip(),
        eff.seed(),
        eff.blackrock_rounds(),
        eff.shard(),
        1,
        0,
        eff.resume_index(),
        eff.resume_count(),
        eff.retries(),
        eff.max_rate(),
        |i, repeats, xxx, ip_them, port_them| {
            if let Err(e) = builder.fill(&mut probe, i, repeats, xxx, ip_them, port_them) {
                return ControlFlow::Break(Err(e));
            }
            match f(&probe) {
                ControlFlow::Break(b) => ControlFlow::Break(Ok(b)),
                ControlFlow::Continue(()) => ControlFlow::Continue(()),
            }
        },
    )?;
    match flow {
        ControlFlow::Continue(()) => Ok(ControlFlow::Continue(())),
        ControlFlow::Break(Ok(b)) => Ok(ControlFlow::Break(b)),
        ControlFlow::Break(Err(e)) => Err(e),
    }
}

#[derive(Debug)]
struct PlanInner {
    effective: EffectiveConfig,
    binding: AdapterBinding,
    range: u64,
    blackrock: BlackRock,
    builder: Builder,
}

/// Проверенный план нового запуска. Поля приватны; создать можно только через
/// [`ReadyPlan::new`].
#[derive(Debug, Clone)]
pub struct ReadyPlan {
    inner: Arc<PlanInner>,
}

impl ReadyPlan {
    pub fn new(
        effective: EffectiveConfig,
        binding: AdapterBinding,
    ) -> Result<ReadyPlan, PlanError> {
        if effective.operation() != Operation::Scan {
            return Err(PlanError::NotScanOperation(effective.operation()));
        }
        if effective.resume_index() != 0 {
            return Err(PlanError::ResumeIndexNotAllowed(effective.resume_index()));
        }
        if let Some(c) = effective.resume_count().filter(|&c| c != 0) {
            return Err(PlanError::ResumeCountNotAllowed(c));
        }
        let shard = effective.shard();
        if shard != Shard::default() {
            return Err(PlanError::UnsupportedShard {
                one: shard.one,
                of: shard.of,
            });
        }
        if effective.retries() != 0 {
            return Err(PlanError::UnsupportedRetries(effective.retries()));
        }
        if effective.blackrock_rounds() != RUNTIME_BLACKROCK_ROUNDS {
            return Err(PlanError::UnsupportedRounds(effective.blackrock_rounds()));
        }
        let builder = Builder::new(&binding, effective.seed())?;
        if let Some(r) = effective
            .massip()
            .ports()
            .as_slice()
            .iter()
            .find(|r| r.end > u32::from(u16::MAX))
        {
            return Err(PlanError::PortNotTcp(r.end));
        }
        let range = effective.massip().try_range().map_err(ScanError::from)?;
        if range == 0 {
            return Err(ScanError::EmptyRange.into());
        }
        let blackrock = BlackRock::try_new(range, effective.seed(), effective.blackrock_rounds())
            .map_err(ScanError::from)?;
        Ok(ReadyPlan {
            inner: Arc::new(PlanInner {
                effective,
                binding,
                range,
                blackrock,
                builder,
            }),
        })
    }

    pub fn effective(&self) -> &EffectiveConfig {
        &self.inner.effective
    }

    pub fn binding(&self) -> &AdapterBinding {
        &self.inner.binding
    }

    /// Число probe плана (комбинации IP/порт).
    pub fn range(&self) -> u64 {
        self.inner.range
    }
}

/// Курсор по probe плана: `current` и `preload` не продвигают, `advance_sent`
/// подтверждает ровно одну успешную отправку, `advance_sent_n` первые `k`
/// загруженных.
pub struct ProbeCursor {
    plan: ReadyPlan,
    stream: Box<dyn Iterator<Item = (u64, u64)> + Send>,
    /// Загруженные, ещё не подтверждённые probe, по порядку индексов.
    loaded: VecDeque<Probe>,
    /// Поток кончился или probe не построился: новых probe нет. Липкий, чтобы
    /// пропущенный индекс не сдвинул последовательность.
    ended: bool,
    position: u64,
}

impl std::fmt::Debug for ProbeCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeCursor")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl ProbeCursor {
    /// Курсор, начинающийся с индекса `next_index` (0 для нового запуска).
    /// `next_index == range` даёт пустой курсор; `> range` это ошибка.
    pub fn new(plan: &ReadyPlan, next_index: u64) -> Result<ProbeCursor, PlanError> {
        let range = plan.range();
        if next_index > range {
            return Err(PlanError::NextIndexBeyondRange { next_index, range });
        }
        let stream = transmit_index_stream(
            range,
            Shard::default(),
            1,
            0,
            next_index,
            None,
            0,
            plan.effective().max_rate(),
        );
        Ok(ProbeCursor {
            plan: plan.clone(),
            stream: Box::new(stream),
            loaded: VecDeque::new(),
            ended: false,
            position: next_index,
        })
    }

    /// Строит следующий probe потока и ставит его в хвост загруженных. `false`
    /// в конце диапазона.
    fn load_one(&mut self) -> bool {
        if self.ended {
            return false;
        }
        let Some((i, x)) = self.stream.next() else {
            self.ended = true;
            return false;
        };
        let inner = &*self.plan.inner;
        let xxx = inner.blackrock.shuffle(x);
        let (ip, port) = inner.effective.massip().pick(xxx);
        let mut p = Probe::default();
        // План уже проверил, что порты помещаются в TCP; при ошибке probe не
        // выдаётся (курсор заканчивается), а не паникует.
        if inner.builder.fill(&mut p, i, 0, xxx, ip, port).is_ok() {
            self.loaded.push_back(p);
            true
        } else {
            self.ended = true;
            false
        }
    }

    /// Текущий неподтверждённый probe; повторный вызов не продвигает.
    /// `None` в конце диапазона.
    pub fn current(&mut self) -> Option<&Probe> {
        if self.loaded.is_empty() {
            self.load_one();
        }
        self.loaded.front()
    }

    /// Загружает до `n` ещё не подтверждённых probe (начиная с текущего) и
    /// отдаёт их по порядку индексов. Не продвигает `position`; повторный вызов
    /// отдаёт те же probe. Короче `n` только в конце диапазона.
    /// Вызывающий ограничивает `n` (движок: `MAX_TX_BATCH`): внутреннего предела нет.
    pub fn preload(&mut self, n: usize) -> &[Probe] {
        while self.loaded.len() < n && self.load_one() {}
        let slice = self.loaded.make_contiguous();
        &slice[..n.min(slice.len())]
    }

    /// Подтверждает ровно один успешно отправленный текущий probe. В конце
    /// диапазона ничего не делает.
    pub fn advance_sent(&mut self) {
        if self.current().is_some() {
            self.advance_sent_n(1);
        }
    }

    /// Подтверждает `k` первых загруженных probe: `position += k`. `k` больше
    /// числа загруженных это ошибка вызывающего (debug assert); в release
    /// подтверждается столько, сколько загружено.
    pub fn advance_sent_n(&mut self, k: usize) {
        debug_assert!(
            k <= self.loaded.len(),
            "advance_sent_n({k}) beyond the {} loaded probes",
            self.loaded.len()
        );
        let k = k.min(self.loaded.len());
        self.loaded.drain(..k);
        self.position += k as u64;
    }

    /// Следующий неподтверждённый индекс.
    pub fn position(&self) -> u64 {
        self.position
    }
}
