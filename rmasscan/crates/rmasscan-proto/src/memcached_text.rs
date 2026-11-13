//! Текстовый разбор ответа memcached: `memcached_tcp_parse` (`src/proto-memcached.c:106-223`). Общий для UDP
//! (`memcached_udp_parse` отдаёт сюда датаграмму без 8-байтового заголовка, `src/proto-memcached.c:361-371`) и TCP
//! (подэтап 4b: тот же автомат на потоке, состояние живёт между сегментами, как `pstate->state` и
//! `memcached->match` у C).
//!
//! Из строк `STAT <имя> <значение>` C оставляет только `uptime`, `time` и `version`: имя, `=`, байты значения до
//! `\n` (CR выбрасывается), пробел (`src/proto-memcached.c:192-219`). Сопоставление ключевых слов у C делает smack
//! (`src/smack1.c`): шаблоны с привязкой к началу (`SMACK_ANCHOR_BEGIN`), без учёта регистра, каждое слово плюс один из
//! байтов ` \t\r\n` (`memcached_init`, `src/proto-memcached.c:227-293`). Ни один шаблон не префикс другого, поэтому
//! автомат smack здесь это проход по префиксам: первое несовпадение уводит его в состояние без привязки, откуда
//! совпадений нет до конца буфера (`smack_stage2_link_fails`, `src/smack1.c:1075-1100`), и поиск съедает всё до конца
//! (`smack_search_next`, `src/smack1.c:1410-1488`). Все странности C повторены: строка после `STAT\n`, `ERROR\n` и
//! других ответов пропускается целиком, неизвестное имя статистики останавливает разбор, после `END` всё
//! игнорируется. Единственное отличие: в состоянии «до конца строки» C читает `px[length]` за буфером
//! (`src/proto-memcached.c:165`); на UDP это не влияет на вывод (состояние дальше не используется), здесь байт не
//! читается.

/// Ответы (`memcached_responses`, `src/proto-memcached.c:47-69`), в нижнем регистре, как их хранит smack
/// (`make_copy_of_pattern`, `src/smack1.c:668-694`). Индекс это `MC_*`.
const RESPONSES: [&[u8]; 20] = [
    b"error",
    b"client_error",
    b"server_error",
    b"stored",
    b"not_stored",
    b"exists",
    b"not_found",
    b"end",
    b"value",
    b"deleted",
    b"touched",
    b"ok",
    b"busy",
    b"badclass",
    b"nospare",
    b"notfull",
    b"unsafe",
    b"same",
    b"stat",
    b"",
];
const MC_END: usize = 7;
const MC_STAT: usize = 18;

/// Имена статистики (`memcached_stats`, `src/proto-memcached.c:87-102`). Индекс это `MS_*`; текст баннера берёт
/// имя отсюда, а не из ответа (`src/proto-memcached.c:195`).
const STATS: [&[u8]; 13] = [
    b"pid",
    b"uptime",
    b"time",
    b"version",
    b"pointer_size",
    b"rusage_user",
    b"rusage_system",
    b"curr_items",
    b"total_items",
    b"bytes",
    b"max_connections",
    b"curr_connections",
    b"total_connections",
];
const MS_UPTIME: usize = 1;
const MS_TIME: usize = 2;
const MS_VERSION: usize = 3;

/// Байты, которые `memcached_init` дописывает к каждому слову (`src/proto-memcached.c:247-248`).
const WORD_END: [u8; 4] = *b" \t\r\n";

/// Самый длинный шаблон: `total_connections` и байт-разделитель.
const MAX_PATTERN: usize = 18;

/// `isspace` в локали C (masscan не вызывает `setlocale`): пробел и 0x09-0x0D.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// Состояние smack для шаблонов с привязкой к началу: совпавший префикс (в нижнем регистре) или «мёртвое»
/// состояние без привязки.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Matcher {
    prefix: [u8; MAX_PATTERN],
    len: usize,
    dead: bool,
}

impl Matcher {
    /// `memcached->match = 0`: начальное состояние (после `swap_rows` это состояние привязки, `src/smack1.c:1199-1203`).
    fn new() -> Self {
        Matcher {
            prefix: [0; MAX_PATTERN],
            len: 0,
            dead: false,
        }
    }

    /// Один байт входа. `Some(id)`, если префикс стал шаблоном целиком.
    fn step(&mut self, table: &[&[u8]], c: u8) -> Option<usize> {
        if self.dead {
            return None;
        }
        // src/smack1.c:1163-1167: 'A'..'Z' переводятся в символы строчных букв.
        let c = c.to_ascii_lowercase();
        let seen = self.prefix.get(..self.len).unwrap_or(&[]);
        let mut extends = false;
        for (id, word) in table.iter().enumerate() {
            if seen == *word && WORD_END.contains(&c) {
                return Some(id);
            }
            if word.starts_with(seen) && word.get(self.len) == Some(&c) {
                extends = true;
            }
        }
        match self.prefix.get_mut(self.len) {
            Some(slot) if extends => {
                *slot = c;
                self.len += 1;
            }
            _ => self.dead = true,
        }
        None
    }

    /// `smack_search_next` с позиции `from`: `(id совпадения, смещение за ним)` или `(None, длина)`, если
    /// совпадения нет до конца буфера.
    fn search(&mut self, table: &[&[u8]], px: &[u8], from: usize) -> (Option<usize>, usize) {
        let mut i = from;
        while let Some(&c) = px.get(i) {
            i += 1;
            if let Some(id) = self.step(table, c) {
                return (Some(id), i);
            }
            if self.dead {
                break;
            }
        }
        (None, px.len())
    }
}

/// Состояния `memcached_tcp_parse` (номера C в комментариях). Состояние 1 у C недостижимо: оно бывает только
/// проваливанием из 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// 0: начало строки, ключевое слово ответа.
    Command,
    /// 2: пропуск до конца строки.
    SkipLine,
    /// 3: после `END` всё игнорируется.
    End,
    /// 100: пробелы после `STAT`.
    StatSpace,
    /// 101: имя статистики.
    StatName,
    /// 200: пробелы перед значением.
    ValueSpace,
    /// 201: значение.
    Value,
}

/// Автомат `memcached_tcp_parse`. Для UDP новый на каждую датаграмму (`memset(stuff, 0, ...)`,
/// `src/proto-memcached.c:365`), для TCP один на соединение.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemcachedText {
    state: State,
    matcher: Matcher,
}

impl MemcachedText {
    pub(crate) fn new() -> Self {
        MemcachedText {
            state: State::Command,
            matcher: Matcher::new(),
        }
    }

    /// Разбирает очередной кусок ответа и дописывает текст баннера `memcached` в `banner`.
    pub(crate) fn parse(&mut self, px: &[u8], banner: &mut Vec<u8>) {
        let mut i = 0;
        while let Some(&c) = px.get(i) {
            match self.state {
                State::Command => {
                    // src/proto-memcached.c:129-154: сопоставление начинается заново на каждом входе в состояние 0,
                    // в том числе в начале следующего сегмента TCP.
                    self.matcher = Matcher::new();
                    let (id, next) = self.matcher.search(&RESPONSES, px, i);
                    // У C `i--` указывает на байт-разделитель совпавшего шаблона.
                    let newline = next.checked_sub(1).and_then(|at| px.get(at)) == Some(&b'\n');
                    match id {
                        None => {}
                        Some(MC_STAT) if newline => self.state = State::SkipLine,
                        Some(MC_STAT) => self.state = State::StatSpace,
                        Some(MC_END) => self.state = State::End,
                        Some(_) => self.state = State::SkipLine,
                    }
                    i = next;
                }
                State::End => return,
                State::SkipLine => {
                    // src/proto-memcached.c:162-167 (без чтения px[length]).
                    match px
                        .get(i..)
                        .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
                    {
                        Some(k) => {
                            self.state = State::Command;
                            i += k + 1;
                        }
                        None => i = px.len(),
                    }
                }
                State::StatSpace | State::ValueSpace => {
                    // src/proto-memcached.c:170-181: непробельный байт переходит в следующее состояние и
                    // разбирается там же (`i--`).
                    if c == b'\n' {
                        self.state = State::Command;
                    } else if !is_space(c) {
                        self.state = if self.state == State::StatSpace {
                            State::StatName
                        } else {
                            State::Value
                        };
                        self.matcher = Matcher::new();
                        continue;
                    }
                    i += 1;
                }
                State::StatName => {
                    // src/proto-memcached.c:182-208: поиск продолжает состояние smack с прошлого вызова.
                    let (id, next) = self.matcher.search(&STATS, px, i);
                    let newline = next.checked_sub(1).and_then(|at| px.get(at)) == Some(&b'\n');
                    match id {
                        None => {}
                        Some(id @ (MS_UPTIME | MS_TIME | MS_VERSION)) => {
                            banner.extend_from_slice(STATS.get(id).copied().unwrap_or(b""));
                            self.state = if newline {
                                State::Command
                            } else {
                                State::ValueSpace
                            };
                            banner.push(b'=');
                        }
                        Some(_) if newline => self.state = State::Command,
                        Some(_) => self.state = State::SkipLine,
                    }
                    i = next;
                }
                State::Value => {
                    // src/proto-memcached.c:210-219
                    if c == b'\n' {
                        banner.push(b' ');
                        self.state = State::Command;
                    } else if c != b'\r' {
                        banner.push(c);
                    }
                    i += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(px: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        MemcachedText::new().parse(px, &mut out);
        out
    }

    /// Ответ на `stats` (как у memcached 1.6): после `libevent` (имени нет в таблице) разбор стоит до конца.
    #[test]
    fn memcached_text_keeps_three_stats() {
        let px = b"STAT pid 1234\r\nSTAT uptime 12345\r\nSTAT time 1700000000\r\nSTAT version 1.6.21\r\n\
                   STAT libevent 2.1.12-stable\r\nSTAT pointer_size 64\r\nSTAT uptime 9\r\nEND\r\n";
        assert_eq!(text(px), b"uptime=12345 time=1700000000 version=1.6.21 ");
    }

    /// Правила строк `memcached_tcp_parse`, каждое с C (`src/proto-memcached.c:127-221`).
    #[test]
    fn memcached_text_line_rules() {
        // Ключевые слова без учёта регистра, имя в баннере из таблицы.
        assert_eq!(text(b"stat UPTIME 5\r\n"), b"uptime=5 ");
        // `STAT\n`: состояние 2 съедает следующую строку целиком.
        assert_eq!(text(b"STAT\nSTAT uptime 1\r\nSTAT time 2\r\n"), b"time=2 ");
        // Любой другой ответ тоже пропускает строку, следующую за ним, если он кончился на `\n`.
        assert_eq!(text(b"ERROR\nSTAT uptime 1\r\nSTAT time 2\r\n"), b"time=2 ");
        assert_eq!(text(b"ERROR\r\nSTAT uptime 1\r\n"), b"uptime=1 ");
        // Пустая строка: шаблон "" плюс разделитель.
        assert_eq!(text(b"\r\nSTAT uptime 1\r\n"), b"uptime=1 ");
        assert_eq!(text(b"\nSTAT uptime 1\r\nSTAT time 2\r\n"), b"time=2 ");
        // Неизвестное имя статистики и неизвестное начало строки: дальше ничего.
        assert_eq!(text(b"STAT foo 1\r\nSTAT uptime 5\r\n"), b"");
        assert_eq!(text(b"HELLO\r\nSTAT uptime 5\r\n"), b"");
        // Известное, но не нужное имя: строка пропускается.
        assert_eq!(text(b"STAT pid 7\r\nSTAT time 8\r\n"), b"time=8 ");
        // END останавливает разбор.
        assert_eq!(text(b"END\r\nSTAT uptime 1\r\n"), b"");
        // Пробелы перед значением пропускаются (isspace, включая \v и \f), внутри значения остаются, CR выпадает.
        assert_eq!(
            text(b"STAT version \x0b\x0c 1.6 beta\r\r\n"),
            b"version=1.6 beta "
        );
        // Имя без значения: `=` без пробела.
        assert_eq!(text(b"STAT uptime\r\nSTAT time \n"), b"uptime=time=");
        assert_eq!(text(b"STAT uptime\nSTAT time 3\n"), b"uptime=time=3 ");
        // Имя кончается только на ` \t\r\n`.
        assert_eq!(text(b"STAT uptime\t7\r\n"), b"uptime=7 ");
        assert_eq!(text(b"STAT uptime:7\r\n"), b"");
        // Значение без конца строки обрывается без пробела.
        assert_eq!(text(b"STAT uptime 12"), b"uptime=12");
        assert_eq!(text(b""), b"");
    }

    /// Состояние живёт между кусками (TCP в 4b): имя статистики может разорваться, а ключевое слово в начале строки
    /// нет: состояние 0 на входе сбрасывает smack (`src/proto-memcached.c:129-131`), как у C.
    #[test]
    fn memcached_text_streams_like_c() {
        let whole = b"STAT uptime 12345\r\nSTAT time 1\r\n";
        for cut in 0..=whole.len() {
            let mut t = MemcachedText::new();
            let mut out = Vec::new();
            t.parse(&whole[..cut], &mut out);
            t.parse(&whole[cut..], &mut out);
            let want: &[u8] = match cut {
                // Разрыв внутри `STAT` первой строки: ничего.
                1..=3 => b"",
                // Второй кусок начинается с пробела: пустой шаблон и разделитель, строка пропускается.
                4 => b"time=1 ",
                // Разрыв внутри `STAT` второй строки: её нет.
                20..=23 => b"uptime=12345 ",
                _ => b"uptime=12345 time=1 ",
            };
            assert_eq!(out, want, "cut {cut}");
        }
    }
}
