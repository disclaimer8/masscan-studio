# Проверка этапа 2B-Linux перед следующим этапом

Дата: 2026-10-24. Проверено дерево `365eb18acac9b33b2bf43e3502c29abfa4fb3a30`,
ветка `feat/rmasscan-stage2b-linux`, [PR #8](https://github.com/disclaimer8/masscan-studio/pull/8).
Исходники не менялись. Проверка включает чтение diff и лабораторного harness,
независимое ревью net/FFI, локальные offline проверки и сверку сохранённых артефактов.
Новый privileged wire scan не запускался.

Во время ревью удалённая ветка обновилась до `df53e6d56cd96aff56159b5c229a48acf29971e5`.
Единственный новый diff — исправление теста переполнения; он просмотрен отдельно.
Результаты полного локального suite ниже относятся к `365eb18`, не к новому HEAD.

## Вывод

Linux explicit-binding реализован и имеет содержательные wire-свидетельства.
Безусловный GO пока преждевременен: новый CI ещё не завершён, ветка конфликтует
с main, два замечания по runtime/test
контрактам остаются, полная performance matrix помечена FAIL самим harness.
Следующий функциональный этап — Windows/Npcap; начать его следует с закрытия
перечисленных ниже пунктов и фиксации новой базы. macOS BPF и Studio — позже.

## Найденные проблемы

### 1. Закрыто новым commit — гонка теста; интеграция с main остаётся

`rmasscan/crates/rmasscan-engine/tests/pause_resume.rs:263` начинает drain сразу
после запуска, хотя тест требует переполнения очереди. Потребитель успевает
освобождать место, поэтому вместо ConsumerTooSlow возможен Completed.

[CI 40058974984](https://github.com/disclaimer8/masscan-studio/actions/runs/40058974984)
упал ровно на этом assertion на Ubuntu и Windows; macOS прошёл.
Это не новый дефект AF_PACKET. Исправление `wait_for("overflow outcome", ...)`
уже находится в main после PR #4/#5 вместе с sha2 0.11.1 и actions/cache v6.
Новый `df53e6d` независимо исправил гонку: ждёт ConsumerTooSlow до чтения,
затем вызывает join_drain. Повторно исправлять её не нужно. При интеграции
актуального main сохранить детерминированное ожидание и assertion на два
сохранённых результата из main. GitHub показывает mergeStateStatus=DIRTY.
[Новый CI](https://github.com/disclaimer8/masscan-studio/actions/runs/40059526042):
на момент финальной сверки macOS PASS, Ubuntu/Windows IN_PROGRESS.

### 2. P2 — повторяющийся EINTR вызывает активное кручение

`rmasscan/crates/rmasscan-net/src/linux/mod.rs:143` и `:258`: после EINTR
цикл повторяет системный вызов без ожидания, проверяя только deadline.
Такие же повторные прерывания poll следует учитывать вместе с send/recv.

Независимый offline harness с production TX/Deadline и синтетическим EINTR
получил 59 085 831 попытку за 1.000005 с, user CPU 0.99 с. Это измерение
тестового syscall seam, не частота настоящих сигналов ядра. Deadline соблюдён,
но требование плана «без busy-spin при потоке EINTR» не выполнено.
Нужен ограниченный backoff с сохранением исходного deadline; тестировать число
попыток/ожидания через seam, не только верхнюю границу wall time.

### 3. P2 — лабораторный тест противоречит kernel outgoing filter

`rmasscan/crates/rmasscan-net/tests/linux_io.rs:202` требует `rx_outgoing >= 1`.
Но `src/linux/socket.rs:74` включает PACKET_IGNORE_OUTGOING: при успехе
исходящий кадр вообще не попадает в RX userspace и счётчик остаётся нулём.
Корректное поведение на поддерживающем эту опцию ядре приводит к FAIL теста.

В live-тесте проверять подтверждённую отправку и отсутствие собственного кадра
на выходе RX. Точный userspace счётчик отдельно проверять через syscall seam
для fallback-пути. Не удалять проверку фильтрации целиком.

### 4. Разрыв в приёмке — performance matrix ещё не полностью валидна

`docs/experiments/2026-10-23-rmasscan-stage2b-linux-raw/perf-round2.results.json`:
`PASS=5, FAIL=1, NOT RUN=0`, валидны 38/40 ячеек. Два Rust-прогона 1k pps
(повторы 1 и 2): tcpdump записал 3091 кадр при received-by-filter=3092.
Harness правильно пометил capture INVALID. Все 3072 SYN захвачены; scanner-side
ответы полны и kernel drops=0. Это не свидетельство потери результата сканером,
но и не полностью успешный performance suite.

Медианы на валидных ячейках укладываются в ±20%: Rust/C ≈1.011, 1.000,
1.004, 1.005 на 100/1k/10k/100k pps. На 1k имеется только 3 валидных Rust-повтора.
Нужно разобраться с завершением capture, сохранить неудачные измерения,
повторить матрицу после исправления; не превращать INVALID в PASS ослаблением
условия и не выбирать удачные повторы без отчёта об остальных.

## Подтверждено в этой проверке

- macOS: `cargo test --locked --workspace` — **298 passed, 0 failed, 7 ignored**.
- Дополнительно на `df53e6d` в изолированном worktree:
  `cargo test --locked -p rmasscan-engine --test pause_resume` — **10/10 PASS**.
- `cargo fmt --all --check`, Clippy `--workspace --all-targets -D warnings`,
  `cargo deny check bans licenses sources` проходят.
- Python comparator `verify-wire.py --self-test` — **31/31**.
- Хэши 12 C-oracle pcap и 6 effective-echo файлов совпадают с manifest.
  Во всех 6 парах повторные C SYN-трассы совпадают по байтам и порядку.
- Сохранённый `rust-round2.results.json`: **120 PASS, 0 FAIL, 0 NOT RUN**,
  включая pause/resume, отрицательные resume, Stop и удаление veth.
  Это перепроверка сохранённых свидетельств; wire-tests заново не выполнялись.
- Исправления двух P2 ревью 2A присутствуют: фильтр итоговых целей/портов и
  сохранение принятых событий после worker panic. Regression-тесты проходят.
- В пределах независимого net-ревью дополнительных дефектов unsafe memory,
  ABI или владения fd не обнаружено; это ограниченный результат ревью.

## Границы результата

Работа с явно заданным source IP/MAC, не назначенным интерфейсу ОС, намеренна:
это совместимость с masscan и текущим лабораторным binding. Старую формулировку
плана о проверке OS-assigned source нужно уточнить, а не возвращать это ограничение.

Физический NIC, Windows/Npcap, macOS/BPF, discovery/ARP, утраты связи/VPN/sleep,
sendqueue и настоящий Scan в Slint этой приёмкой не закрыты. Ubuntu-стенд
использовал 26.04.1; это не фактический wire-прогон на минимальной Ubuntu 24.04.
Windows Server 2022 в GitHub проверяет сборку и offline-тесты, не Windows 11/Npcap.

Следующий план: [2B-Windows](../superpowers/plans/2026-10-24-rmasscan-stage2b-windows.md).
