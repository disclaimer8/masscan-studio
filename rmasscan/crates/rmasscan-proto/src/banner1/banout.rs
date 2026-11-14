//! Буферы баннеров соединения, `struct BannerOutput` (`src/proto-banout.c`, `src/proto-banout.h:15-21`, справка B3):
//! одна запись на тип приложения, порядок списка C, предел записи 65 536 байт (Р5) и бюджет байтов таблицы
//! ([`ByteBudget`]).
//!
//! Порядок записей у C зависит от устройства списка: голова встроена в TCB (200 байт, не перевыделяется), новая
//! запись занимает пустую голову или встаёт сразу за ней, а голова, которой мало места, переезжает в новый узел за
//! собой и пустеет (`banout_expand`, `:258-286`), и её место берёт следующая новая запись. Здесь список это вектор,
//! голова в нём первая; длина C (`length`) ведётся рядом с хранимыми байтами, поэтому голова переезжает на том же
//! дописывании, что у C, даже когда предел Р5 или бюджет сохранили меньше байтов.

use rmasscan_core::banner::MAX_BANNER_BYTES;

use crate::tcp::app::ByteBudget;

/// Запись списка: `protocol`, `length` C и сохранённые байты (не больше [`MAX_BANNER_BYTES`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Rec {
    app: u16,
    c_len: usize,
    bytes: Vec<u8>,
}

/// Буферы баннеров одного соединения (`tcb->banout`). Пустой вектор это свежий `banout_init`: пустая голова.
#[derive(Debug, Default)]
pub(crate) struct Banout {
    recs: Vec<Rec>,
}

/// Ёмкость головы списка: `unsigned char banner[200]` (`src/proto-banout.h:20`). Голова встроена в TCB и не
/// перевыделяется; записи за ней растут на месте, их ёмкость на порядок не влияет.
const HEAD_CAPACITY: usize = 200;

impl Banout {
    /// `banout_append(banout, app, px, length)` (`src/proto-banout.c:326-363`): запись по точному `protocol`
    /// (`banout_find_proto`, `:48-54`) или новая (`banout_new_proto`, `:237-253`); голова, которой не хватает места
    /// (`length + n >= max_length`), переезжает за себя (`banout_expand`, `:258-286`). Байты за пределом
    /// [`MAX_BANNER_BYTES`] не хранятся и бюджет не трогают (Р5); из остального сохраняется то, что дал бюджет.
    pub(crate) fn append(&mut self, budget: &mut ByteBudget, app: u16, px: &[u8]) {
        if self.recs.is_empty() {
            self.recs.push(Rec::default());
        }
        let mut at = match self.recs.iter().position(|r| r.app == app) {
            Some(i) => i,
            None => self.new_proto(app),
        };
        if at == 0
            && let Some(head) = self.recs.first_mut()
            && head.c_len.saturating_add(px.len()) >= HEAD_CAPACITY
        {
            // `:269-273`: копия головы встаёт сразу за ней, голова `protocol = 0, length = 0`.
            let moved = std::mem::take(head);
            self.recs.insert(1, moved);
            at = 1;
        }
        let Some(rec) = self.recs.get_mut(at) else {
            return;
        };
        // Р5: запись это первые 65 536 байт записи C; дальше позиции не хранятся. Из позиций в пределе хранится то,
        // что дал бюджет, недостача считается в бюджете.
        let room = MAX_BANNER_BYTES.saturating_sub(rec.c_len);
        rec.c_len = rec.c_len.saturating_add(px.len());
        let got = budget.take(px.len().min(room));
        push_bounded(&mut rec.bytes, px.get(..got).unwrap_or(px));
    }

    /// `banout_new_proto` (`src/proto-banout.c:237-253`): пустая голова (`protocol == 0 && length == 0`) берёт `app`,
    /// иначе новая запись встаёт сразу за головой. Номер записи.
    fn new_proto(&mut self, app: u16) -> usize {
        match self.recs.first_mut() {
            Some(head) if head.app == 0 && head.c_len == 0 => {
                head.app = app;
                0
            }
            Some(_) => {
                self.recs.insert(
                    1,
                    Rec {
                        app,
                        ..Rec::default()
                    },
                );
                1
            }
            None => {
                self.recs.push(Rec {
                    app,
                    ..Rec::default()
                });
                0
            }
        }
    }

    /// Запись `app` целиком, вынутая из списка: её байты возвращаются в бюджет. Для повтора HEUR (справка E2.1,
    /// E1.3): до классификации в списке только запись HEUR, и после неё список пуст, как у C на неразрезанном потоке.
    pub(crate) fn take(&mut self, budget: &mut ByteBudget, app: u16) -> Vec<u8> {
        let rec = match self.recs.iter().position(|r| r.app == app) {
            Some(0) => self.recs.first_mut().map(std::mem::take),
            Some(i) => Some(self.recs.remove(i)),
            None => None,
        };
        let bytes = rec.map(|r| r.bytes).unwrap_or_default();
        budget.give(bytes.len());
        if self.recs.iter().all(|r| *r == Rec::default()) {
            self.recs.clear();
        }
        bytes
    }

    /// `banner_flush` (`src/stack-tcp-core.c:810-828`): записи с `length && protocol` в порядке списка, байты
    /// возвращаются в бюджет, список пуст (`banout_release`). Запись, от которой бюджет не оставил ни байта, не
    /// выдаётся.
    pub(crate) fn flush(&mut self, budget: &mut ByteBudget) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        for r in std::mem::take(&mut self.recs) {
            budget.give(r.bytes.len());
            if r.app != 0 && r.c_len != 0 && !r.bytes.is_empty() {
                out.push((r.app, r.bytes));
            }
        }
        out
    }

    /// Узлы списка `(protocol, length C)`, голова первой.
    #[cfg(test)]
    pub(crate) fn nodes(&self) -> Vec<(u16, usize)> {
        self.recs.iter().map(|r| (r.app, r.c_len)).collect()
    }

    /// Сохранённых байтов во всех записях.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.recs.iter().map(|r| r.bytes.len()).sum()
    }
}

/// Дописать с ростом ёмкости не дальше [`MAX_BANNER_BYTES`] (удвоение `Vec` иначе выделило бы до двух пределов).
fn push_bounded(v: &mut Vec<u8>, px: &[u8]) {
    let need = v.len().saturating_add(px.len());
    if need > v.capacity() {
        let want = v
            .capacity()
            .saturating_mul(2)
            .min(MAX_BANNER_BYTES)
            .max(need);
        v.reserve_exact(want - v.len());
    }
    v.extend_from_slice(px);
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/tcp-banners"
    );

    fn read(name: &str) -> String {
        std::fs::read_to_string(format!("{GOLDEN}/{name}"))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    /// Байт `k` дописывания сценария: `(seed + 131 * k) & 0xFF` (`tcp_oracle.c`, режим `banout`).
    fn payload(len: usize, seed: usize) -> Vec<u8> {
        (0..len).map(|k| ((seed + 131 * k) & 0xFF) as u8).collect()
    }

    /// `"..."` с `\xNN` вывода оракула.
    fn unquote(tok: &str) -> Vec<u8> {
        let b = tok
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .expect("quoted")
            .as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' {
                let h = std::str::from_utf8(&b[i + 2..i + 4]).expect("hex");
                out.push(u8::from_str_radix(h, 16).expect("hex"));
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }

    type Script = (String, Vec<(u16, Vec<u8>)>);

    fn scripts() -> Vec<Script> {
        let mut out: Vec<Script> = Vec::new();
        for line in read("banout.in.txt").lines() {
            if let Some(name) = line.strip_prefix("script ") {
                out.push((name.to_owned(), Vec::new()));
            } else if let Some(rest) = line.strip_prefix("append ") {
                let v: Vec<usize> = rest
                    .split(' ')
                    .map(|w| w.parse().expect("number"))
                    .collect();
                let app = u16::try_from(v[0]).expect("app");
                out.last_mut()
                    .expect("script")
                    .1
                    .push((app, payload(v[1], v[2])));
            }
        }
        out
    }

    /// Сценарий C: имя, узлы, записи.
    type CResult = (String, Vec<(u16, usize)>, Vec<(u16, Vec<u8>)>);

    /// Узлы `(protocol, length)` и записи `banner_flush` сценариев C.
    fn c_results() -> Vec<CResult> {
        let mut out = Vec::new();
        for line in read("banout.out").lines().skip(1) {
            if let Some(name) = line.strip_prefix("script ") {
                out.push((name.to_owned(), Vec::new(), Vec::new()));
            } else if let Some(rest) = line.strip_prefix("node ") {
                let (p, l) = rest.split_once(' ').expect("node");
                let p = u16::from_str_radix(p.strip_prefix("protocol=0x").expect("protocol"), 16)
                    .expect("hex");
                let l: usize = l
                    .strip_prefix("length=")
                    .expect("length")
                    .parse()
                    .expect("len");
                out.last_mut().expect("script").1.push((p, l));
            } else if let Some(rest) = line.strip_prefix("record ") {
                let mut w = rest.splitn(3, ' ');
                let app: u16 = w.next().expect("app").parse().expect("app");
                let len: usize = w.next().expect("len").parse().expect("len");
                let bytes = unquote(w.next().expect("bytes"));
                assert_eq!(bytes.len(), len);
                out.last_mut().expect("script").2.push((app, bytes));
            } else {
                assert_eq!(line, "end", "unexpected oracle line");
            }
        }
        out
    }

    /// Порядок списка C (справка B3) на прямых дописываниях, сверенный с `banout_append` C (`banout.out` эталонов):
    /// пустая голова занимается, новая запись встаёт за головой, голова переезжает, когда `length + n >= 200`, и её
    /// место берёт следующая новая запись; запись не в голове растёт на месте; пустое дописывание создаёт запись.
    #[test]
    fn banout_order_matches_c() {
        let scripts = scripts();
        let c = c_results();
        assert_eq!(scripts.len(), c.len());
        assert_eq!(scripts.len(), 12);
        for ((name, appends), (c_name, c_nodes, c_records)) in scripts.iter().zip(&c) {
            assert_eq!(name, c_name);
            let mut b = Banout::default();
            let mut budget = ByteBudget::new(usize::MAX);
            for (app, px) in appends {
                b.append(&mut budget, *app, px);
            }
            assert_eq!(&b.nodes(), c_nodes, "{name}: nodes");
            assert_eq!(&b.flush(&mut budget), c_records, "{name}: records");
            assert_eq!(budget.left(), usize::MAX, "{name}: budget back");
            assert!(b.nodes().is_empty(), "{name}: released");
        }
    }

    /// Р5: запись не длиннее 65 536 байт, байты за пределом не берутся из бюджета и не считаются выброшенными; длина
    /// C растёт дальше (порядок списка от неё). Бюджет обрезает внутри предела и считает недостачу.
    #[test]
    fn banout_caps_record_at_65536() {
        let mut b = Banout::default();
        let mut budget = ByteBudget::new(1 << 20);
        b.append(&mut budget, app_id_heur(), &vec![b'a'; 70_000]);
        b.append(&mut budget, app_id_heur(), b"tail");
        b.append(&mut budget, 4, b"other");
        assert_eq!(b.nodes(), [(4, 5), (1, 70_004)]);
        assert_eq!(b.held(), MAX_BANNER_BYTES + 5);
        assert_eq!(budget.left(), (1 << 20) - MAX_BANNER_BYTES - 5);
        assert_eq!(budget.dropped(), 0);
        let recs = b.flush(&mut budget);
        assert_eq!(recs[0], (4, b"other".to_vec()));
        assert_eq!(recs[1], (1, vec![b'a'; MAX_BANNER_BYTES]));
        assert_eq!(budget.left(), 1 << 20);

        // По байту до предела и за ним.
        let mut b = Banout::default();
        for _ in 0..MAX_BANNER_BYTES + 10 {
            b.append(&mut budget, 1, b"z");
        }
        assert_eq!(b.held(), MAX_BANNER_BYTES);
        assert_eq!(b.flush(&mut budget), [(1, vec![b'z'; MAX_BANNER_BYTES])]);

        // Бюджет меньше предела: сохранено столько, сколько дал бюджет, недостача внутри предела считается.
        let mut small = ByteBudget::new(100);
        let mut b = Banout::default();
        b.append(&mut small, 1, &vec![b'q'; 70_000]);
        assert_eq!(b.held(), 100);
        assert_eq!(small.dropped(), (MAX_BANNER_BYTES - 100) as u64);
        b.append(&mut small, 4, b"x");
        assert_eq!(small.dropped(), (MAX_BANNER_BYTES - 100 + 1) as u64);
        // Запись без байтов (всё отнял бюджет) не выдаётся.
        assert_eq!(b.flush(&mut small), [(1, vec![b'q'; 100])]);
        assert_eq!(small.left(), 100);
    }

    /// Вынутая запись HEUR оставляет список, каким его застаёт парсер на неразрезанном потоке у C: пустым, и
    /// следующая новая запись берёт голову.
    #[test]
    fn take_leaves_the_list_as_if_never_written() {
        for len in [5usize, 199, 200, 450] {
            let mut budget = ByteBudget::new(1000);
            let mut b = Banout::default();
            b.append(&mut budget, 1, &vec![7; len]);
            assert_eq!(b.take(&mut budget, 1), vec![7; len], "{len}");
            assert_eq!(budget.left(), 1000);
            b.append(&mut budget, 31, b"s");
            b.append(&mut budget, 4, b"h");
            assert_eq!(b.nodes(), [(31, 1), (4, 1)], "{len}");
            assert!(b.take(&mut budget, 1).is_empty());
        }
    }

    fn app_id_heur() -> u16 {
        crate::app::app_id::HEUR
    }
}
