//! Генерация probe: SYN-cookie, порт источника и кадр (AGPL-3.0). Порт
//! формулы `transmit_thread` (`src/main.c:371-402`) из masscan © Robert David
//! Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0). Формула
//! перенесена из CLI без изменения байтов; перестановка и индексы берутся из
//! [`crate::scan`] и [`crate::blackrock`], здесь они не переписаны.
//!
//! Два входа:
//! - [`ReadyPlan`] + [`ProbeCursor`]: runtime. Курсор отдаёт один и тот же
//!   probe, пока вызывающий не подтвердит отправку ([`ProbeCursor::advance_sent`]).
//!   [`ReadyPlan::new`] принимает только то, что runtime v1 умеет (shard 1/1,
//!   NIC 1, retries 0, rounds 14) и только новый запуск: продолжение идёт через
//!   checkpoint, не через `resume_index`/`resume_count`. [`ReadyPlan::new_cli`]
//!   принимает любой валидный shard, retries до 999, `resume_*` и до 8 адаптеров.
//! - [`for_each_probe`]: потоковый оракул для CLI (`--offline --packet-trace`),
//!   сохраняет все алгоритмы этапа 1 (retries, shard), с остановкой через
//!   [`ControlFlow`].

use std::collections::VecDeque;
use std::iter::Peekable;
use std::ops::ControlFlow;
use std::sync::Arc;

use crate::blackrock::BlackRock;
use crate::config::{EffectiveConfig, Operation};
use crate::cookie::syn_cookie_ipv4;
use crate::packet::{LinkType, TcpSynTemplate};
use crate::scan::{ScanError, Shard, transmit_bounds, transmit_index_stream, transmit_scan_flow};

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
    #[error("invalid shard {one}/{of}: need 1 <= one <= of")]
    InvalidShard { one: u32, of: u32 },
    #[error("retries must be at most 999, got {0}")]
    TooManyRetries(u32),
    #[error("blackrock rounds must be at least 1, got {0}")]
    ZeroRounds(u32),
    #[error("need 1..=8 adapters, got {0}")]
    BadNicCount(usize),
    #[error("adapter index {index} is out of range for {count} adapters")]
    NicIndexOutOfRange { index: u32, count: usize },
    #[error("invalid source addresses {first:#010x}-{last:#010x}: need first <= last")]
    InvalidSourceIpv4 { first: u32, last: u32 },
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

/// Адаптер плана CLI: [`AdapterBinding`] плюс диапазон адресов источника и
/// режим C для не-степени-двойки ширины портов. Студия остаётся на
/// [`AdapterBinding`]: его 6 полей заморожены.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicBinding {
    pub binding: AdapterBinding,
    /// Последний адрес источника (включительно); `ipv4_mask = last - first`
    /// (main.c:183). Равен `binding.source_ipv4` для одного адреса.
    pub source_ipv4_last: u32,
    /// C сам пишет в `paused.conf` порты `p-(p+16)` (17 портов, не степень
    /// двойки; main.c:1318, main-conf.c:3668). С флагом ширина принимается и
    /// маска остаётся `last - first` (main.c:186).
    pub legacy_c_17_port_mask: bool,
}

impl From<AdapterBinding> for NicBinding {
    fn from(binding: AdapterBinding) -> NicBinding {
        NicBinding {
            source_ipv4_last: binding.source_ipv4,
            legacy_c_17_port_mask: false,
            binding,
        }
    }
}

/// Одна отправка SYN (main.c:371-402).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    /// Внешний индекс цикла `i` (main.c:431): при `retries > 0` или shard это
    /// не порядковый номер кадра, а один `i` на всю пачку повторов.
    pub index: u64,
    pub ip_me: u32,
    pub port_me: u16,
    pub ip_them: u32,
    pub port_them: u16,
    pub seqno: u32,
    pub frame: Vec<u8>,
}

fn check_source_ports(first: u16, last: u16, legacy_width: bool) -> Result<(), PlanError> {
    let width = u32::from(last)
        .wrapping_sub(u32::from(first))
        .wrapping_add(1);
    if first == 0 || first > last || !(legacy_width || width.is_power_of_two()) {
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
    /// main.c:183 `ipv4_mask = ipv4.last - ipv4.first`.
    ipv4_mask: u32,
    entropy: u64,
}

impl Builder {
    fn new(binding: &AdapterBinding, seed: u64) -> Result<Builder, PlanError> {
        Builder::from_nic(&NicBinding::from(binding.clone()), seed)
    }

    fn from_nic(nic: &NicBinding, seed: u64) -> Result<Builder, PlanError> {
        let binding = &nic.binding;
        let (first, last) = binding.source_ports;
        check_source_ports(first, last, nic.legacy_c_17_port_mask)?;
        if nic.source_ipv4_last < binding.source_ipv4 {
            return Err(PlanError::InvalidSourceIpv4 {
                first: binding.source_ipv4,
                last: nic.source_ipv4_last,
            });
        }
        Ok(Builder {
            tmpl: TcpSynTemplate::new(binding.source_mac, binding.next_hop_mac, binding.link_type),
            ip_me0: binding.source_ipv4,
            ipv4_mask: nic.source_ipv4_last - binding.source_ipv4,
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
        let ipv4_mask = self.ipv4_mask;
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
    nics: Vec<NicBinding>,
    range: u64,
    blackrock: BlackRock,
    /// По одному на адаптер (у каждого свои адреса и порты источника).
    builders: Vec<Builder>,
}

/// Проверенный план нового запуска. Поля приватны; создать можно только через
/// [`ReadyPlan::new`] или [`ReadyPlan::new_cli`].
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
        ReadyPlan::build(effective, vec![NicBinding::from(binding)])
    }

    /// План CLI: любой валидный shard, retries до 999, `resume_index` и
    /// `resume_count` из конфигурации, 1..=8 адаптеров (main.c:212-223,
    /// :269-273). `ReadyPlan::new` для Студии остаётся прежним.
    pub fn new_cli(
        effective: EffectiveConfig,
        nics: Vec<NicBinding>,
    ) -> Result<ReadyPlan, PlanError> {
        if effective.operation() != Operation::Scan {
            return Err(PlanError::NotScanOperation(effective.operation()));
        }
        let shard = effective.shard();
        if shard.one == 0 || shard.one > shard.of {
            return Err(PlanError::InvalidShard {
                one: shard.one,
                of: shard.of,
            });
        }
        if effective.retries() > 999 {
            return Err(PlanError::TooManyRetries(effective.retries()));
        }
        if effective.blackrock_rounds() < 1 {
            return Err(PlanError::ZeroRounds(effective.blackrock_rounds()));
        }
        ReadyPlan::build(effective, nics)
    }

    fn build(effective: EffectiveConfig, nics: Vec<NicBinding>) -> Result<ReadyPlan, PlanError> {
        if nics.is_empty() || nics.len() > 8 {
            return Err(PlanError::BadNicCount(nics.len()));
        }
        let builders = nics
            .iter()
            .map(|n| Builder::from_nic(n, effective.seed()))
            .collect::<Result<Vec<_>, _>>()?;
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
                nics,
                range,
                blackrock,
                builders,
            }),
        })
    }

    pub fn effective(&self) -> &EffectiveConfig {
        &self.inner.effective
    }

    /// Привязка первого адаптера (для плана `new` единственного).
    pub fn binding(&self) -> &AdapterBinding {
        &self.inner.nics[0].binding
    }

    /// Адаптеры плана по порядку `nic[0..n)`.
    pub fn nics(&self) -> &[NicBinding] {
        &self.inner.nics
    }

    /// Число probe плана (комбинации IP/порт).
    pub fn range(&self) -> u64 {
        self.inner.range
    }

    /// Смещение потока адаптера в базе `resume.index`:
    /// `(shard.one - 1) * nic_count + nic_index` (main.c:269, 32-битное произведение).
    pub fn nic_offset(&self, nic_index: u32) -> u64 {
        let one = self.inner.effective.shard().one;
        let count = self.inner.nics.len() as u32;
        u64::from(one.wrapping_sub(1).wrapping_mul(count)).wrapping_add(u64::from(nic_index))
    }

    /// Конец цикла адаптера `nic_index`, `main.c:269-273`:
    /// `min(range, start + resume_count) + retries * range`, где
    /// `start = resume_index + (shard.one - 1) * nic_count + nic_index`.
    pub fn effective_end(&self, nic_index: u32) -> u64 {
        let (_, end) = self.bounds(nic_index, self.inner.effective.resume_index());
        end
    }

    /// `(start, end)` потока адаптера при базе `resume_index` (main.c:269-273).
    fn bounds(&self, nic_index: u32, base: u64) -> (u64, u64) {
        let e = &self.inner.effective;
        let (start, end, _) = transmit_bounds(
            self.inner.range,
            e.shard(),
            self.inner.nics.len() as u32,
            nic_index,
            base,
            e.resume_count(),
            e.retries(),
        );
        (start, end)
    }

    /// Курсор потока адаптера `nic_index` (`main.c:212-223, :269-273, :328-334,
    /// :421-431`). `resume_override` заменяет `resume.index` (база, к которой
    /// C прибавляет смещение shard и NIC); `None` берёт его из конфигурации.
    pub fn cursor_for_nic(
        &self,
        nic_index: u32,
        resume_override: Option<u64>,
    ) -> Result<ProbeCursor, PlanError> {
        let count = self.inner.nics.len();
        if nic_index as usize >= count {
            return Err(PlanError::NicIndexOutOfRange {
                index: nic_index,
                count,
            });
        }
        let e = &self.inner.effective;
        let range = self.inner.range;
        let base = resume_override.unwrap_or_else(|| e.resume_index());
        // C проверки не делает (main.c:269-280); возобновление на хвосте
        // повторов (range < base < конец) законно. Предел: `(retries+1)*range`,
        // при retries == 0 это `range` (путь v1 и engine.rs:760).
        let limit = range.saturating_add(u64::from(e.retries()).saturating_mul(range));
        if base > limit {
            return Err(PlanError::NextIndexBeyondRange {
                next_index: base,
                range: limit,
            });
        }
        let (start, end) = self.bounds(nic_index, base);
        let stream = transmit_index_stream(
            range,
            e.shard(),
            count as u32,
            nic_index,
            base,
            e.resume_count(),
            e.retries(),
            e.max_rate(),
        );
        let stream: Box<dyn Iterator<Item = (u64, u64)> + Send> = Box::new(stream);
        let mut cursor = ProbeCursor {
            plan: self.clone(),
            nic_index: nic_index as usize,
            stream: stream.peekable(),
            loaded: VecDeque::new(),
            ended: false,
            failed: false,
            blackrock: self.inner.blackrock,
            repeats: 0,
            position: start,
            end,
        };
        cursor.refresh_position();
        Ok(cursor)
    }
}

/// Курсор по probe плана: `current` и `preload` не продвигают, `advance_sent`
/// подтверждает ровно одну успешную отправку, `advance_sent_n` первые `k`
/// загруженных.
pub struct ProbeCursor {
    plan: ReadyPlan,
    nic_index: usize,
    stream: Peekable<Box<dyn Iterator<Item = (u64, u64)> + Send>>,
    /// Загруженные, ещё не подтверждённые probe, по порядку индексов.
    loaded: VecDeque<Probe>,
    /// Поток кончился или probe не построился: новых probe нет. Липкий, чтобы
    /// пропущенный индекс не сдвинул последовательность.
    ended: bool,
    /// Probe не построился (порт не влез в TCP): конец не естественный, и `--infinite` не перезапускает проход.
    failed: bool,
    /// Перестановка текущего прохода: у прохода `n` это `BlackRock(seed + n)` (`main.c:225-228, 445-449`), у
    /// прохода 0 перестановка плана.
    blackrock: BlackRock,
    /// Счётчик `--infinite` (`repeats` в C): номер прохода, входит в `(unsigned)(i + repeats)` (`main.c:379`).
    repeats: u64,
    /// Внешний индекс `i` следующего неподтверждённого probe (main.c:431
    /// `parms->my_index = i`), не число отправленных кадров.
    position: u64,
    /// `effective_end` потока: позиция после последнего кадра.
    end: u64,
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
    /// При `retries == 0`: `next_index == range` даёт пустой курсор, `> range`
    /// ошибка. При `retries > 0` пределом служит `(retries + 1) * range`.
    pub fn new(plan: &ReadyPlan, next_index: u64) -> Result<ProbeCursor, PlanError> {
        plan.cursor_for_nic(0, Some(next_index))
    }

    /// Нормализованная база возобновления: `position()` без смещения shard/NIC,
    /// то есть значение для `cursor_for_nic(nic, Some(base))` (смещение
    /// прибавляется внутри, повторно его учитывать не нужно).
    pub fn resume_base(&self) -> u64 {
        self.position
            .saturating_sub(self.plan.nic_offset(self.nic_index as u32))
    }

    /// Ставит `position` по внешнему индексу: голова загруженных, иначе
    /// следующий `i` потока, иначе `end`.
    fn refresh_position(&mut self) {
        self.position = match self.loaded.front() {
            Some(p) => p.index,
            None => match self.stream.peek() {
                Some(&(i, _)) => i,
                None => self.end,
            },
        };
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
        let builder = &inner.builders[self.nic_index];
        let xxx = self.blackrock.shuffle(x);
        let (ip, port) = inner.effective.massip().pick(xxx);
        let mut p = Probe::default();
        // План уже проверил, что порты помещаются в TCP; при ошибке probe не
        // выдаётся (курсор заканчивается), а не паникует.
        if builder.fill(&mut p, i, self.repeats, xxx, ip, port).is_ok() {
            self.loaded.push_back(p);
            true
        } else {
            self.ended = true;
            self.failed = true;
            false
        }
    }

    /// Номер прохода `--infinite` (0 для первого).
    pub fn repeats(&self) -> u64 {
        self.repeats
    }

    /// Следующий проход `--infinite` (`main.c:445-449` `seed++; repeats++; goto infinite`, метка на `:251`).
    /// Только когда `effective.infinite()` включён и текущий проход дошёл до `effective_end` (поток исчерпан и всё
    /// отправлено): тогда пересоздаёт `BlackRock::new(range, seed + repeats + 1, rounds)` (`:262`), увеличивает
    /// `repeats` и сбрасывает поток на начало (`:269-273`) с базой 0: `resume-index` действует только на первом
    /// проходе (спец Р5; сознательное отличие от C, где метка `:251` стоит до `start = resume.index + ...`), так что
    /// следующие проходы покрывают весь диапазон. `end` пересчитывается для нового прохода.
    /// `entropy` построителя остаётся исходным `seed` (`:227` `entropy = masscan->seed` задан до метки), поэтому
    /// `seqno` и порт источника проверяются приёмом для обоих проходов. `true`, если проход начат заново.
    pub fn advance_pass(&mut self) -> bool {
        let e = self.plan.effective();
        if !e.infinite() || self.failed || !self.loaded.is_empty() || self.stream.peek().is_some() {
            return false;
        }
        let inner = &*self.plan.inner;
        let next = self.repeats.wrapping_add(1);
        let Ok(blackrock) = BlackRock::try_new(
            inner.range,
            e.seed().wrapping_add(next),
            e.blackrock_rounds(),
        ) else {
            return false;
        };
        let stream = transmit_index_stream(
            inner.range,
            e.shard(),
            inner.nics.len() as u32,
            self.nic_index as u32,
            0,
            e.resume_count(),
            e.retries(),
            e.max_rate(),
        );
        let (_, end) = self.plan.bounds(self.nic_index as u32, 0);
        let stream: Box<dyn Iterator<Item = (u64, u64)> + Send> = Box::new(stream);
        let mut stream = stream.peekable();
        // Пустой проход (`resume-count` отсёк всё) не перезапускается: движок крутился бы вхолостую.
        if stream.peek().is_none() {
            return false;
        }
        self.stream = stream;
        self.end = end;
        self.blackrock = blackrock;
        self.repeats = next;
        self.ended = false;
        self.refresh_position();
        true
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

    /// Подтверждает `k` первых загруженных probe; `position` идёт по внешнему индексу. `k` больше
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
        self.refresh_position();
    }

    /// Следующий неподтверждённый индекс.
    pub fn position(&self) -> u64 {
        self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ScanConfig, validate};
    use crate::massip::MassIp;
    use crate::targets::{add_target_string, parse_ports};
    use std::collections::BTreeSet;

    const IP_ME: u32 = 0x0aff_0001;
    const MAC_ME: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_NH: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

    fn binding() -> AdapterBinding {
        AdapterBinding {
            interface_id: "test0".to_string(),
            link_type: LinkType::Ethernet,
            source_ipv4: IP_ME,
            source_mac: MAC_ME,
            next_hop_mac: MAC_NH,
            source_ports: (40000, 40003),
        }
    }

    fn nics(n: u32) -> Vec<NicBinding> {
        (0..n)
            .map(|k| {
                let mut b = binding();
                b.interface_id = format!("test{k}");
                NicBinding::from(b)
            })
            .collect()
    }

    fn eff(targets: &str, ports: &str, f: impl FnOnce(&mut ScanConfig)) -> EffectiveConfig {
        let mut m = MassIp::new();
        add_target_string(m.ipv4_mut(), targets).unwrap();
        parse_ports(m.ports_mut(), ports).unwrap();
        let mut cfg = ScanConfig {
            targets: m,
            seed: 0x1234_5678,
            ..ScanConfig::default()
        };
        f(&mut cfg);
        validate(&cfg, Operation::Scan).unwrap()
    }

    fn drain(cursor: &mut ProbeCursor) -> Vec<Probe> {
        let mut out = Vec::new();
        while let Some(p) = cursor.current().cloned() {
            out.push(p);
            cursor.advance_sent();
        }
        out
    }

    fn oracle(e: &EffectiveConfig) -> Vec<Probe> {
        let mut out = Vec::new();
        let flow = for_each_probe(e, &binding(), |p| {
            out.push(p.clone());
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
        assert_eq!(flow, ControlFlow::Continue(()));
        out
    }

    // 37 целей: 198.18.0.0-198.18.0.36 x порт 80 (простой range, не кратный шагу).
    const T37: &str = "198.18.0.0-198.18.0.36";

    #[test]
    fn shards_partition_full_range_without_gaps_or_overlaps() {
        let all = oracle(&eff(T37, "80", |_| {}));
        assert_eq!(all.len(), 37);
        let want: BTreeSet<_> = all.iter().map(|p| (p.ip_them, p.port_them)).collect();
        assert_eq!(want.len(), 37);
        let mut seen = BTreeSet::new();
        let mut total = 0;
        for one in 1..=3 {
            let e = eff(T37, "80", |c| c.shard = Shard { one, of: 3 });
            let want_shard = oracle(&e);
            let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
            let got = drain(&mut plan.cursor_for_nic(0, None).unwrap());
            assert_eq!(got, want_shard, "shard {one}/3 differs from for_each_probe");
            total += got.len();
            for p in got {
                assert!(seen.insert((p.ip_them, p.port_them)), "overlap {p:?}");
            }
        }
        assert_eq!(total, 37);
        assert_eq!(seen, want);
    }

    #[test]
    fn shards_partition_multi_port_range_with_cartesian_excludes() {
        let mut t = MassIp::new();
        add_target_string(t.ipv4_mut(), "198.18.0.0/29").unwrap();
        parse_ports(t.ports_mut(), "80-84").unwrap();
        let mut ex = MassIp::new();
        add_target_string(ex.ipv4_mut(), "198.18.0.5-198.18.0.7").unwrap();
        t.apply_excludes(&mut ex);
        let mut seen = BTreeSet::new();
        let mut total = 0;
        for one in 1..=3 {
            let cfg = ScanConfig {
                targets: t.clone(),
                seed: 0x1234_5678,
                shard: Shard { one, of: 3 },
                ..ScanConfig::default()
            };
            let plan =
                ReadyPlan::new_cli(validate(&cfg, Operation::Scan).unwrap(), nics(1)).unwrap();
            assert_eq!(plan.range(), 25);
            for p in drain(&mut plan.cursor_for_nic(0, None).unwrap()) {
                total += 1;
                assert!(seen.insert((p.ip_them, p.port_them)), "overlap {p:?}");
            }
        }
        assert_eq!(total, 25);
        assert_eq!(seen.len(), 25);
        let ports: BTreeSet<_> = seen.iter().map(|&(_, port)| port).collect();
        assert_eq!(ports.len(), 5);
    }

    #[test]
    fn resume_on_retry_tail_is_accepted() {
        let e = eff("198.18.0.0-198.18.0.9", "80", |c| c.retries = 2);
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        // range = 10, конец = 30: база 15 лежит на хвосте повторов.
        let mut cursor = plan.cursor_for_nic(0, Some(15)).unwrap();
        assert_eq!(cursor.position(), 15);
        assert_eq!(drain(&mut cursor).len(), (30 - 15) * 3);
        assert_eq!(cursor.position(), 30);
        assert!(matches!(
            plan.cursor_for_nic(0, Some(31)),
            Err(PlanError::NextIndexBeyondRange { .. })
        ));
        // retries == 0 (путь v1): `> range` по-прежнему ошибка.
        let v1 = ReadyPlan::new_cli(eff("198.18.0.0-198.18.0.9", "80", |_| {}), nics(1)).unwrap();
        assert!(ProbeCursor::new(&v1, 10).is_ok());
        assert!(ProbeCursor::new(&v1, 11).is_err());
    }

    #[test]
    fn resume_base_strips_shard_and_nic_offset() {
        let e = eff(T37, "80", |c| c.shard = Shard { one: 2, of: 3 });
        let plan = ReadyPlan::new_cli(e, nics(2)).unwrap();
        assert_eq!(plan.nic_offset(1), 3);
        let cursor = plan.cursor_for_nic(1, Some(6)).unwrap();
        assert_eq!(cursor.position(), 9);
        assert_eq!(cursor.resume_base(), 6);
        let again = plan.cursor_for_nic(1, Some(cursor.resume_base())).unwrap();
        assert_eq!(again.position(), 9);
    }

    #[test]
    fn multi_nic_and_shards_match_c_increment() {
        let mut all = BTreeSet::new();
        let mut total = 0;
        for one in 1..=3u32 {
            let e = eff(T37, "80", |c| c.shard = Shard { one, of: 3 });
            let plan = ReadyPlan::new_cli(e, nics(2)).unwrap();
            for nic in 0..2u32 {
                let idx: Vec<u64> = drain(&mut plan.cursor_for_nic(nic, None).unwrap())
                    .iter()
                    .map(|p| p.index)
                    .collect();
                // main.c:269 start = (one-1)*nic_count + nic_index, шаг main.c:223.
                let start = u64::from((one - 1) * 2 + nic);
                if one == 2 {
                    assert_eq!(idx[0], 2 + u64::from(nic));
                }
                assert_eq!(idx[0], start);
                assert!(idx.windows(2).all(|w| w[1] - w[0] == 6));
                total += idx.len();
                all.extend(idx);
            }
        }
        assert_eq!(total, 37);
        assert_eq!(all, (0..37).collect::<BTreeSet<u64>>());
    }

    #[test]
    fn retries_stream_matches_for_each_probe() {
        let e = eff("198.18.0.0-198.18.0.9", "80", |c| {
            c.retries = 2;
            c.max_rate = 7.0;
        });
        let want = oracle(&e);
        assert_eq!(want.len(), (2 + 1) * (2 + 1) * 10);
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        assert_eq!(plan.effective_end(0), 10 + 2 * 10);
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        let got = drain(&mut cursor);
        assert_eq!(got.len(), 90);
        assert_eq!(got, want);
        assert_eq!(cursor.position(), 30);
    }

    #[test]
    fn cursor_tracks_outer_index_across_retries_and_shards() {
        let e = eff("198.18.0.0-198.18.0.9", "80", |c| {
            c.retries = 2;
            c.shard = Shard { one: 1, of: 2 };
        });
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        assert_eq!(cursor.position(), 0);
        cursor.advance_sent();
        assert_eq!(cursor.position(), 0);
        cursor.advance_sent();
        assert_eq!(cursor.position(), 0);
        cursor.advance_sent();
        assert_eq!(cursor.position(), 2);
        // preload не двигает позицию; подтверждение k кадров из пачки тоже
        // считается по внешнему индексу.
        assert_eq!(cursor.preload(4).len(), 4);
        assert_eq!(cursor.position(), 2);
        cursor.advance_sent_n(2);
        assert_eq!(cursor.position(), 2);
        cursor.advance_sent_n(2);
        assert_eq!(cursor.position(), 4);
    }

    /// `--infinite` (main.c:225-228, :445-449): второй проход идёт с `seed + 1` и `repeats = 1`, а SYN-cookie
    /// остаётся на исходном `entropy`, поэтому приём подтверждает SYN-ACK обоих проходов.
    #[test]
    fn infinite_restarts_with_incremented_seed_and_constant_entropy() {
        let e = eff("198.18.0.0-198.18.0.3", "80", |c| {
            c.seed = 10;
            c.infinite = true;
        });
        let rounds = e.blackrock_rounds();
        let first_oracle = oracle(&eff("198.18.0.0-198.18.0.3", "80", |c| c.seed = 10));
        let plan = ReadyPlan::new_cli(e.clone(), nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        // Проход не закончился: перезапуска нет.
        assert!(!cursor.advance_pass());
        let mut got = Vec::new();
        for _ in 0..4 {
            let p = cursor.current().cloned().unwrap();
            got.push(p);
            cursor.advance_sent();
        }
        assert_eq!(cursor.repeats(), 0);
        assert_eq!(got, first_oracle, "pass 0 equals the seed=10 oracle");
        assert!(cursor.current().is_none());
        assert!(cursor.advance_pass());
        assert_eq!(cursor.repeats(), 1);
        assert_eq!(cursor.position(), 0);
        let second = drain(&mut cursor);
        assert_eq!(second.len(), 4);
        // Порядок целей второго прохода это BlackRock(seed = 11); `seqno` и порт источника считаются с entropy = 10,
        // а `i + repeats` (main.c:379) даёт `n = i + 1`.
        let br = BlackRock::try_new(4, 11, rounds).unwrap();
        for (i, p) in second.iter().enumerate() {
            let xxx = br.shuffle(i as u64);
            let (ip, port) = e.massip().pick(xxx);
            assert_eq!((p.ip_them, u32::from(p.port_them)), (ip, port), "i={i}");
            let n = i as u64 + 1;
            let ck = syn_cookie_ipv4(n as u32, 0, xxx as u32, (xxx >> 32) as u32, 10);
            assert_eq!(u32::from(p.port_me), 40000 + (ck as u32 & 3), "i={i}");
            assert_eq!(p.ip_me, IP_ME);
            let want = syn_cookie_ipv4(ip, port, p.ip_me, u32::from(p.port_me), 10) as u32;
            assert_eq!(p.seqno, want, "i={i}: entropy stays the initial seed");
            assert_eq!(p.index, i as u64);
        }
        let order = |v: &[Probe]| v.iter().map(|p| p.ip_them).collect::<Vec<_>>();
        assert_ne!(order(&second), order(&got), "a new seed reshuffles");
        // Третий проход: seed = 12, repeats = 2.
        assert!(cursor.advance_pass());
        assert_eq!(cursor.repeats(), 2);
    }

    #[test]
    fn advance_pass_is_a_noop_without_infinite() {
        let e = eff("198.18.0.0-198.18.0.3", "80", |_| {});
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        assert_eq!(drain(&mut cursor).len(), 4);
        assert!(!cursor.advance_pass());
        assert!(cursor.current().is_none());
    }

    /// Р5: `resume-index` действует только на первом проходе, дальше проходы покрывают весь диапазон.
    #[test]
    fn infinite_later_passes_ignore_resume_index() {
        let e = eff("198.18.0.0-198.18.0.5", "80", |c| {
            c.seed = 10;
            c.infinite = true;
            c.resume_index = 4;
        });
        let rounds = e.blackrock_rounds();
        let plan = ReadyPlan::new_cli(e.clone(), nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        let first: Vec<u64> = drain(&mut cursor).iter().map(|p| p.index).collect();
        assert_eq!(first, [4, 5]);
        assert!(cursor.advance_pass());
        let second = drain(&mut cursor);
        assert_eq!(
            second.iter().map(|p| p.index).collect::<Vec<_>>(),
            [0, 1, 2, 3, 4, 5]
        );
        let br = BlackRock::try_new(6, 11, rounds).unwrap();
        for p in &second {
            // main.c:328 `xXx = i + r * rate`, затем по модулю range.
            let x = (p.index + e.max_rate() as u64) % 6;
            let (ip, port) = e.massip().pick(br.shuffle(x));
            assert_eq!((p.ip_them, u32::from(p.port_them)), (ip, port));
        }
        // Третий проход тоже полный.
        assert!(cursor.advance_pass());
        assert_eq!(drain(&mut cursor).len(), 6);
    }

    /// `end` нового прохода пересчитывается: после исчерпания `position()` равен его концу, а не концу прохода 0.
    #[test]
    fn infinite_restart_recomputes_the_pass_end() {
        let e = eff("198.18.0.0-198.18.0.5", "80", |c| {
            c.infinite = true;
            c.resume_index = 1;
            c.resume_count = Some(2);
        });
        let plan = ReadyPlan::new_cli(e, nics(1)).unwrap();
        let mut cursor = plan.cursor_for_nic(0, None).unwrap();
        assert_eq!(drain(&mut cursor).len(), 2);
        assert_eq!(cursor.position(), 3, "pass 0 ends at resume_index + count");
        assert!(cursor.advance_pass());
        assert_eq!(drain(&mut cursor).len(), 2);
        assert_eq!(cursor.position(), 2, "pass 1 starts at 0: end = 0 + count");
    }
}
