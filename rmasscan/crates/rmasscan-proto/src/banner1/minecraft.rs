//! Парсер баннера Minecraft: `mc_parse` (`src/proto-mc.c:47-90`) masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0), AGPL-3.0; справка D11, E1.13, E2.7.
//!
//! На неразрезанном потоке C считает `{`/`}` по всему сегменту, закрывает, если счётчик `<= 0`, и тогда же
//! дописывает сегмент сырым целиком (`:59-67`); при счётчике `> 0` байты копятся в `banmem` ради вырезания
//! фавикона, с потерей первого байта каждого накопленного сегмента и чтением освобождённой памяти на
//! следующих сегментах (`:68-89`, E1.13). По правилу E2.7 результат здесь не зависит от нарезки: каждый
//! увиденный байт ждёт в отложенной записи под общим бюджетом (как тени RDP), закрытие повторяет проверку C
//! в конце каждого вызова, а на сбросе сессии запись становится баннером только при счётчике `<= 0` — сырой
//! поток целиком, фавикон не вырезается; при счётчике `> 0` отложенные байты выбрасываются, их бюджет
//! возвращается, а уже посчитанные отказы бюджета остаются в `banner_bytes_dropped`.

use crate::app::app_id;

use super::banout::Banout;
use super::session::{ParseCx, Parser};

/// `pstate->sub.mc` без `banmem`: накопленные байты держит отложенная запись [`Banout`].
#[derive(Default)]
pub(crate) struct Minecraft {
    /// `int brackcount` (`src/proto-banner1.h:133`); переполнение у C не определено, здесь оборачивается.
    brackcount: i32,
    held: Banout,
}

impl Parser for Minecraft {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        // `src/proto-mc.c:59-65`: сначала скобки всего сегмента, потом закрытие по итоговому счётчику.
        for &c in px {
            match c {
                b'{' => self.brackcount = self.brackcount.wrapping_add(1),
                b'}' => self.brackcount = self.brackcount.wrapping_sub(1),
                _ => {}
            }
        }
        if !px.is_empty() {
            self.held.append(cx.budget, app_id::MC, px);
        }
        if self.brackcount <= 0 {
            cx.close();
        }
    }

    fn flush(&mut self, cx: &mut ParseCx<'_>) {
        if self.brackcount <= 0 {
            cx.banout.commit_deferred_mc(&mut self.held, cx.budget);
        } else {
            drop(self.held.flush(cx.budget));
        }
    }
}
