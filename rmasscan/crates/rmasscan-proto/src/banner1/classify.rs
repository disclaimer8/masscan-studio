//! Классификатор первых байтов потока: таблица `patterns[]` (`src/proto-banner1.c:34-106`) и автомат smack над ней
//! (`src/smack1.c`), собранный как в `banner1_create` (`smack_create("banner1", SMACK_CASE_INSENSITIVE)`, шаблон `i`
//! с номером `i` и флагами шаблона, `smack_compile`; `src/proto-banner1.c:507-515`), справка B2.
//!
//! Автомат переносится сборкой C, а не описанием её свойств: бор шаблонов (строчными, `tolower`), ссылки неудачи
//! обходом в ширину, достройка переходов, обмен строк 0 и 1 (поиск начинается в строке якоря), сжатие алфавита в
//! символы и правка `*` (`smack_fixup_wildcards`). Отсюда свойства, которые проверяет оракул: регистр важен только
//! для A-Z; якорь это смещение 0 всего потока, частичное якорное совпадение продолжается в следующем сегменте, любой
//! байт, не продолжающий якорный шаблон, гасит все якорные до конца потока; совпадение с самым ранним концом, один
//! номер за вызов; `*` это любой байт, кроме первого байта безъякорного шаблона (0x7B и 0xFF здесь).

/// `SMACK_ANCHOR_BEGIN` (`src/smack.h`).
pub(crate) const ANCHOR_BEGIN: u8 = 0x01;
/// `SMACK_WILDCARDS` (`src/smack.h`).
pub(crate) const WILDCARDS: u8 = 0x08;

/// `struct Patterns` (`src/proto-banner1.h`): байты, приложение, флаги smack (`is_anchored`), `extra`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Pattern {
    pub(crate) bytes: &'static [u8],
    pub(crate) app: u16,
    pub(crate) flags: u8,
    pub(crate) extra: u8,
}

const fn p(bytes: &'static [u8], app: u16, flags: u8, extra: u8) -> Pattern {
    Pattern {
        bytes,
        app,
        flags,
        extra,
    }
}

const A: u8 = ANCHOR_BEGIN;
const AW: u8 = ANCHOR_BEGIN | WILDCARDS;

/// `patterns[]` (`src/proto-banner1.c:34-106`) по порядку: номер шаблона это индекс. Шаблон `"\xff\xfb%\x25xff\xfb"`
/// C с длиной 5 это байты `ff fb 25 25 78` (ошибка экранирования C, повторяется).
pub(crate) const PATTERNS: [Pattern; 60] = [
    p(b"\x00\x00**\xffSMB", 10, AW, 0),
    p(b"\x00\x00**\xfeSMB", 10, AW, 0),
    p(b"\x82\x00\x00\x00", 10, A, 0),
    p(b"\x83\x00\x00\x01\x80", 10, A, 0),
    p(b"\x83\x00\x00\x01\x81", 10, A, 0),
    p(b"\x83\x00\x00\x01\x82", 10, A, 0),
    p(b"\x83\x00\x00\x01\x83", 10, A, 0),
    p(b"\x83\x00\x00\x01\x8f", 10, A, 0),
    p(b"{\x22", 32, 0, 0),
    p(b"SSH-1.", 2, A, 0),
    p(b"SSH-2.", 3, A, 0),
    p(b"HTTP/1.", 4, A, 0),
    p(b"220-", 5, A, 0),
    p(b"220 ", 5, A, 1),
    p(b"+OK ", 12, A, 0),
    p(b"* OK ", 13, A, 0),
    p(b"521 ", 11, A, 0),
    p(b"\x16\x03\x00", 9, A, 0),
    p(b"\x16\x03\x01", 9, A, 0),
    p(b"\x16\x03\x02", 9, A, 0),
    p(b"\x16\x03\x03", 9, A, 0),
    p(b"\x15\x03\x00", 9, A, 0),
    p(b"\x15\x03\x01", 9, A, 0),
    p(b"\x15\x03\x02", 9, A, 0),
    p(b"\x15\x03\x03", 9, A, 0),
    p(b"RFB 000.000\n", 33, A, 1),
    p(b"RFB 003.003\n", 33, A, 3),
    p(b"RFB 003.005\n", 33, A, 3),
    p(b"RFB 003.006\n", 33, A, 3),
    p(b"RFB 003.007\n", 33, A, 7),
    p(b"RFB 003.008\n", 33, A, 8),
    p(b"RFB 003.889\n", 33, A, 8),
    p(b"RFB 003.009\n", 33, A, 8),
    p(b"RFB 004.000\n", 33, A, 8),
    p(b"RFB 004.001\n", 33, A, 8),
    p(b"RFB 004.002\n", 33, A, 8),
    p(b"STAT pid ", 25, A, 0),
    p(b"\xff\xfb\x01\xff\xf0", 29, 0, 0),
    p(b"\xff\xfb\x01\xff\xfb", 29, 0, 0),
    p(b"\xff\xfb\x01\xff\xfc", 29, 0, 0),
    p(b"\xff\xfb\x01\xff\xfd", 29, 0, 0),
    p(b"\xff\xfb\x01\xff\xfe", 29, 0, 0),
    p(b"\xff\xfb\x01\x0a\x0d", 29, 0, 0),
    p(b"\xff\xfb\x01\x0d\x0a", 29, 0, 0),
    p(b"\xff\xfb\x01\x0d\x0d", 29, 0, 0),
    p(b"\xff\xfb\x01\x0a\x0a", 29, 0, 0),
    p(b"\xff\xfb\x25\x25\x78", 29, 0, 0),
    p(b"\xff\xfb\x26\xff\xfd", 29, 0, 0),
    p(b"\xff\xfd\x18\xff\xfd", 29, 0, 0),
    p(b"\xff\xfd\x20\xff\xfd", 29, 0, 0),
    p(b"\xff\xfd\x23\xff\xfd", 29, 0, 0),
    p(b"\xff\xfd\x27\xff\xfd", 29, 0, 0),
    p(b"\xff\xfb\x01\x1b[", 29, A, 0),
    p(b"\xff\xfb\x01Input", 29, A, 0),
    p(b"\xff\xfb\x01   ", 29, A, 0),
    p(b"\xff\xfb\x01login", 29, A, 0),
    p(b"login:", 29, A, 0),
    p(b"password:", 29, A, 0),
    p(
        b"\x03\x00\x00\x13\x0e\xd0\xbe\xef\x12\x34\x00\x02",
        30,
        A,
        0,
    ),
    p(
        b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02",
        30,
        A,
        0,
    ),
];

/// Алфавит сборки: 256 байтов и два псевдосимвола якорей (`CHAR_ANCHOR_START = 256`, `CHAR_ANCHOR_END = 257`,
/// `src/smack1.c:186-196`).
const ALPHABET: usize = 258;
const CHAR_ANCHOR_START: usize = 256;
/// Пустой переход промежуточной таблицы (`FAIL`, `src/smack1.c:205`).
const FAIL: u32 = u32::MAX;
/// Корень без якоря после обмена строк (`UNANCHORED_STATE`, `src/smack1.c:209`); поиск начинается в строке 0, строке
/// якоря.
const UNANCHORED: u32 = 1;

/// Собранный автомат smack: таблица переходов по символам и номера шаблонов строк-совпадений.
#[derive(Debug)]
pub(crate) struct Classifier {
    /// `char_to_symbol` (`src/smack1.c:610-656`, A-Z как строчные, `:1163-1167`).
    char_to_symbol: [u8; 256],
    /// Ширина строки: символы 1..=N и символ 0 прочих байтов.
    width: usize,
    /// `table[row * width + symbol]`.
    table: Vec<u32>,
    /// `m_match[row].m_ids`: номера шаблонов, свой первым, затем по ссылкам неудачи (`smack_copy_matches`).
    matches: Vec<Vec<usize>>,
}

/// Состояние поиска `tcb_state->state` (`smack_search_next`, `src/smack1.c:1410-1490`): строка в младших 24 битах,
/// число ещё не выданных номеров совпадения в старших 8.
pub(crate) type SearchState = u32;

/// `smack_copy_matches` (`src/smack1.c:561-604`): дописать номера, которых ещё нет.
fn copy_matches(row: &mut Vec<usize>, ids: &[usize]) {
    for id in ids {
        if !row.contains(id) {
            row.push(*id);
        }
    }
}

/// Номер строки как индекс (строк меньше 2^24, `compiled_table_fits`).
fn ix(row: u32) -> usize {
    usize::try_from(row).unwrap_or(usize::MAX)
}

/// Номер новой строки.
fn row_no(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(FAIL)
}

impl Classifier {
    /// Автомат `banner1_create` над [`PATTERNS`], один на процесс.
    pub(crate) fn banner1() -> &'static Classifier {
        static C: std::sync::OnceLock<Classifier> = std::sync::OnceLock::new();
        C.get_or_init(|| Classifier::compile(&PATTERNS))
    }

    /// `smack_compile` (`src/smack1.c:1152-1230`) для регистронезависимого автомата (`SMACK_CASE_INSENSITIVE`) без
    /// `SMACK_ANCHOR_END` и `SMACK_SNMP_HACK` (в таблице баннеров их нет).
    fn compile(patterns: &[Pattern]) -> Classifier {
        let lower: Vec<Vec<u8>> = patterns
            .iter()
            .map(|p| p.bytes.to_ascii_lowercase())
            .collect();
        let anchored = patterns.iter().any(|p| p.flags & ANCHOR_BEGIN != 0);

        // Символы (`smack_add_symbols`, `:636-656`): каждый байт шаблонов строчными, затем якорь начала (`:1157-1160`).
        let mut symbol_to_char: Vec<usize> = vec![0];
        let mut char_to_symbol = [0usize; ALPHABET];
        let mut add_symbol = |c: usize| {
            if symbol_to_char.iter().skip(1).any(|&x| x == c) {
                return;
            }
            symbol_to_char.push(c);
            if let Some(slot) = char_to_symbol.get_mut(c) {
                *slot = symbol_to_char.len() - 1;
            }
        };
        for p in &lower {
            for b in p {
                add_symbol(usize::from(*b));
            }
        }
        if anchored {
            add_symbol(CHAR_ANCHOR_START);
        }
        let symbols = symbol_to_char.len() - 1;
        for c in b'A'..=b'Z' {
            char_to_symbol[usize::from(c)] = char_to_symbol[usize::from(c.to_ascii_lowercase())];
        }

        // Stage 0 (`smack_stage0_compile_prefixes`, `:856-895`): бор, корень 0, строка якоря 1.
        let max =
            1 + lower.len() + lower.iter().map(Vec::len).sum::<usize>() + usize::from(anchored);
        let mut goto = vec![[FAIL; ALPHABET]; max];
        let mut fail = vec![0u32; max];
        let mut matches: Vec<Vec<usize>> = vec![Vec::new(); max];
        let mut count = 1usize;
        if anchored {
            goto[0][CHAR_ANCHOR_START] = row_no(count);
            count += 1;
        }
        for (id, (p, bytes)) in patterns.iter().zip(&lower).enumerate() {
            // `smack_add_prefixes` (`:794-853`).
            let mut state = 0u32;
            if p.flags & ANCHOR_BEGIN != 0 {
                state = goto[0][CHAR_ANCHOR_START];
            }
            let mut i = 0;
            while i < bytes.len() && goto[ix(state)][usize::from(bytes[i])] != FAIL {
                state = goto[ix(state)][usize::from(bytes[i])];
                i += 1;
            }
            for b in &bytes[i..] {
                let new = row_no(count);
                count += 1;
                goto[ix(state)][usize::from(*b)] = new;
                state = new;
            }
            copy_matches(&mut matches[ix(state)], &[id]);
        }
        goto.truncate(count);
        fail.truncate(count);
        matches.truncate(count);
        for cell in goto[0].iter_mut() {
            if *cell == FAIL {
                *cell = 0;
            }
        }

        // Stage 1 (`smack_stage1_generate_fails`, `:898-955`): ссылки неудачи обходом в ширину, совпадения цели
        // неудачи дописываются.
        let mut queue = std::collections::VecDeque::new();
        for &s in &goto[0] {
            if s != 0 {
                queue.push_back(s);
                fail[ix(s)] = 0;
            }
        }
        while let Some(r) = queue.pop_front() {
            let row = goto[ix(r)];
            for (a, &s) in row.iter().enumerate() {
                if s == FAIL || s == r {
                    continue;
                }
                queue.push_back(s);
                let mut f = fail[ix(r)];
                // Цепочка неудач кончается в корне, у которого переходов FAIL нет; не длиннее числа строк.
                for _ in 0..count {
                    if goto[ix(f)][a] != FAIL {
                        break;
                    }
                    f = fail[ix(f)];
                }
                let target = goto[ix(f)][a];
                fail[ix(s)] = target;
                let inherited = matches[ix(target)].clone();
                copy_matches(&mut matches[ix(s)], &inherited);
            }
        }

        // Stage 2 (`smack_stage2_link_fails`, `:958-991`): пустые переходы берутся у строки неудачи.
        let mut queue: std::collections::VecDeque<u32> =
            goto[0].iter().copied().filter(|&s| s != 0).collect();
        while let Some(r) = queue.pop_front() {
            let fallback = goto[ix(fail[ix(r)])];
            for (cell, &f) in goto[ix(r)].iter_mut().zip(fallback.iter()) {
                if *cell == FAIL {
                    *cell = f;
                } else if *cell != r {
                    queue.push_back(*cell);
                }
            }
        }

        // Обмен строк 0 и 1 (`swap_rows`, `:1041-1072`, `:1201-1203`): поиск начинается в строке якоря.
        if anchored && count > 1 {
            goto.swap(0, 1);
            matches.swap(0, 1);
            for row in &mut goto {
                for cell in row.iter_mut() {
                    *cell = match *cell {
                        0 => 1,
                        1 => 0,
                        x => x,
                    };
                }
            }
        }
        // `smack_stage3_sort` (`:1074-1104`) только переставляет строки (совпадения в конец) и смысла не меняет.

        // Stage 4 (`smack_stage4_make_final_table`, `:993-1039`): по символам, последний записанный столбец
        // выигрывает (для символа 0 это `CHAR_ANCHOR_END`, переход прочего байта).
        let width = symbols + 1;
        let mut table = vec![0u32; count * width];
        for (row, cells) in goto.iter().enumerate() {
            for (col, cell) in cells.iter().enumerate() {
                table[row * width + char_to_symbol[col]] = *cell;
            }
        }
        let mut c = Classifier {
            char_to_symbol: char_to_symbol_bytes(&char_to_symbol),
            width,
            table,
            matches,
        };

        // `smack_fixup_wildcards` (`:1106-1150`): в строке после байтов до `*` каждый переход в корень без якоря
        // ведёт туда же, куда `*`; переходы в другие строки (первые байты безъякорных шаблонов) остаются.
        let base = if anchored { UNANCHORED } else { 0 };
        for (p, bytes) in patterns.iter().zip(&lower) {
            if p.flags & WILDCARDS == 0 {
                continue;
            }
            for j in 0..bytes.len() {
                if bytes[j] != b'*' {
                    continue;
                }
                let mut state: SearchState = 0;
                let mut offset = 0usize;
                while offset < j {
                    let before = (offset, state);
                    c.search_next(&mut state, &bytes[..j], &mut offset);
                    if (offset, state) == before {
                        break;
                    }
                }
                let row = ix(state & 0x00FF_FFFF);
                let star = usize::from(c.char_to_symbol[usize::from(b'*')]);
                let Some(next) = c.table.get(row * c.width + star).copied() else {
                    continue;
                };
                for k in 0..c.width {
                    if let Some(cell) = c.table.get_mut(row * c.width + k)
                        && *cell == base
                    {
                        *cell = next;
                    }
                }
            }
        }
        c
    }

    /// `smack_search_next` (`src/smack1.c:1410-1490`): без невыданных совпадений идёт по байтам с `offset` до первой
    /// строки-совпадения (`inner_match`), `offset` за её байтом; затем выдаёт последний невыданный номер. Как у C,
    /// строка-совпадение на входе без байтов совпадает снова (`:1463-1467`); `banner1_parse` пустым не зовёт.
    fn search_next(&self, state: &mut SearchState, px: &[u8], offset: &mut usize) -> Option<usize> {
        let mut row = *state & 0x00FF_FFFF;
        let mut current = usize::try_from(*state >> 24).unwrap_or(0);
        let mut i = *offset;
        if current == 0 {
            while let Some(&b) = px.get(i) {
                let sym = usize::from(self.char_to_symbol[usize::from(b)]);
                row = self
                    .table
                    .get(ix(row).saturating_mul(self.width).saturating_add(sym))
                    .copied()
                    .unwrap_or(0);
                if self.is_match(row) {
                    break;
                }
                i += 1;
            }
            if let Some(m) = self.matches.get(ix(row))
                && !m.is_empty()
            {
                i = i.saturating_add(1);
                current = m.len();
            }
        }
        *offset = i;
        let id = if current > 0 {
            current -= 1;
            self.matches
                .get(ix(row))
                .and_then(|m| m.get(current))
                .copied()
        } else {
            None
        };
        *state = row | (u32::try_from(current).unwrap_or(0) << 24);
        id
    }

    fn is_match(&self, row: u32) -> bool {
        self.matches.get(ix(row)).is_some_and(|m| !m.is_empty())
    }

    /// `smack_search_next(smack, state, px, &offset, length)` с `offset` 0, как один вызов `banner1_parse`
    /// (`src/proto-banner1.c:127-134`): номер шаблона первого совпадения или `None`.
    pub(crate) fn search(&self, state: &mut SearchState, px: &[u8]) -> Option<usize> {
        let mut offset = 0;
        self.search_next(state, px, &mut offset)
    }

    #[cfg(test)]
    fn rows(&self) -> usize {
        self.matches.len()
    }

    #[cfg(test)]
    fn symbols(&self) -> usize {
        self.width - 1
    }
}

/// `char_to_symbol` байтов (`unsigned char`, символов меньше 256: `compiled_table_fits`).
fn char_to_symbol_bytes(c: &[usize; ALPHABET]) -> [u8; 256] {
    let mut out = [0u8; 256];
    for (o, s) in out.iter_mut().zip(c.iter()) {
        *o = u8::try_from(*s).unwrap_or(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/tcp-banners"
    );

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Таблица [`PATTERNS`] совпадает с `patterns[]` C, как её видит `banner1_create` (вывод оракула
    /// `patterns.out`): порядок (номер шаблона), приложение, флаги smack, `extra`, длина и байты.
    #[test]
    fn classifier_matches_c_table() {
        let text = std::fs::read_to_string(format!("{GOLDEN}/patterns.out")).expect("patterns.out");
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("tcp-oracle patterns count=60"));
        let mut n = 0;
        for (i, line) in lines.enumerate() {
            let w: Vec<&str> = line.split(' ').collect();
            assert_eq!(w[0], "pattern");
            assert_eq!(w[1], i.to_string());
            let field = |k: &str, at: usize| w[at].strip_prefix(k).expect(k).to_owned();
            let p = PATTERNS[i];
            assert_eq!(field("app=", 2), p.app.to_string(), "pattern {i}");
            assert_eq!(
                field("flags=", 3),
                format!("0x{:x}", p.flags),
                "pattern {i}"
            );
            assert_eq!(field("extra=", 4), p.extra.to_string(), "pattern {i}");
            assert_eq!(field("len=", 5), p.bytes.len().to_string(), "pattern {i}");
            assert_eq!(unhex(w[6]), p.bytes, "pattern {i}");
            n += 1;
        }
        assert_eq!(n, PATTERNS.len());
    }

    /// Каждый шаблон, поданный один, находится под своим номером, в том числе в другом регистре (A-Z); шаблоны SMB с
    /// буквальными `**`.
    #[test]
    fn every_pattern_finds_itself() {
        let c = Classifier::banner1();
        for (i, p) in PATTERNS.iter().enumerate() {
            for bytes in [
                p.bytes.to_vec(),
                p.bytes.to_ascii_lowercase(),
                p.bytes.to_ascii_uppercase(),
            ] {
                let mut st = 0;
                assert_eq!(
                    c.search(&mut st, &bytes),
                    Some(i),
                    "pattern {i} {bytes:02x?}"
                );
            }
        }
    }

    /// Состояние smack переживает вызов: якорное совпадение через границу сегментов, безъякорное тоже; ведущий байт
    /// гасит якорь до конца потока, а безъякорный шаблон находится и после него.
    #[test]
    fn search_state_spans_calls_and_anchor_is_stream_offset_zero() {
        let c = Classifier::banner1();
        let mut st = 0;
        assert_eq!(c.search(&mut st, b"HT"), None);
        assert_eq!(c.search(&mut st, b"tp/1.0 200"), Some(11));
        let mut st = 0;
        assert_eq!(c.search(&mut st, b"xx\xff\xfb"), None);
        assert_eq!(c.search(&mut st, b"\x01\xff\xfd"), Some(40));
        let mut st = 0;
        assert_eq!(c.search(&mut st, b" "), None);
        assert_eq!(c.search(&mut st, b"SSH-2.0-x"), None);
        assert_eq!(c.search(&mut st, b"{\"a\""), Some(8));
        // Самый ранний конец: `{"` раньше, чем кончился бы якорный шаблон.
        let mut st = 0;
        assert_eq!(c.search(&mut st, b"\x00\x00{\"SMB"), Some(8));
    }

    /// `*` SMB это любой байт, кроме первого байта безъякорного шаблона (`smack_fixup_wildcards`,
    /// `src/smack1.c:1106-1150`; эталоны `smb-star-*`).
    #[test]
    fn smb_star_takes_every_byte_but_7b_and_ff() {
        let c = Classifier::banner1();
        for b in 0..=255u8 {
            for at in [2usize, 3] {
                let mut s = b"\x00\x00AB\xffSMB".to_vec();
                s[at] = b;
                let mut st = 0;
                let want = if b == 0x7b || b == 0xff {
                    None
                } else {
                    Some(0)
                };
                assert_eq!(c.search(&mut st, &s), want, "byte {b:02x} at {at}");
            }
        }
    }

    /// Автомат помещается в представление: строк меньше 2^24 (состояние C), символов меньше 256.
    #[test]
    fn compiled_table_fits() {
        let c = Classifier::banner1();
        assert!(c.rows() < 1 << 24);
        assert!(c.symbols() < 256);
    }
}
