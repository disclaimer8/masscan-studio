//! Таблица маршрутов `GetIpForwardTable2`: владение (`FreeMibTable` ровно один раз), приведение байтов BOOLEAN строк к
//! 0/1 и чистый обход строк. Отдельный модуль, чтобы приватность полей замыкала инвариант [`TableRef`]: построить его
//! можно только здесь.

use std::marker::PhantomData;
use std::ptr::NonNull;

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::ADDRESS_FAMILY;

/// Таблица `GetIpForwardTable2`, освобождаемая `FreeMibTable` ровно один раз. Строится только [`MibTable::get`].
pub(super) struct MibTable(NonNull<MIB_IPFORWARD_TABLE2>);

impl MibTable {
    /// `GetIpForwardTable2(family)`: `Ok(None)` при `ERROR_NOT_FOUND` и при пустом указателе, иначе `Err(код)`.
    /// Только чтение.
    pub(super) fn get(family: ADDRESS_FAMILY) -> Result<Option<MibTable>, u32> {
        let mut t: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        // SAFETY: выходной указатель на живой локальный объект; при успехе API выделяет таблицу, которую освобождает
        // `MibTable`.
        let rc = unsafe { GetIpForwardTable2(family, &mut t) };
        match rc {
            NO_ERROR => Ok(NonNull::new(t).map(MibTable)),
            ERROR_NOT_FOUND => Ok(None),
            e => Err(e),
        }
    }
}

impl Drop for MibTable {
    fn drop(&mut self) {
        // SAFETY: указатель получен из успешного GetIpForwardTable2 (не null), наружу не копируется и освобождается
        // ровно один раз.
        unsafe { FreeMibTable(self.0.as_ptr().cast()) };
    }
}

/// Память таблицы в раскладке `MIB_IPFORWARD_TABLE2`, которой владеет реализация: заголовок, за которым в одном
/// выделении, доступном на запись, подряд лежат `NumEntries` строк с `Table[0]`. Байты BOOLEAN строк могут быть любыми.
/// Реализации только в этом модуле: [`MibTable`] (таблица API, наша до `FreeMibTable`) и тестовый `RawTable` (длина
/// проверена при постройке).
pub(super) trait TableMemory {
    /// Голова таблицы; годна, пока `self` заимствован.
    fn head(&mut self) -> NonNull<MIB_IPFORWARD_TABLE2>;

    /// Переписывает на месте четыре байта BOOLEAN каждой строки в 0/1 (`u8::from(байт != 0)`) и заимствует таблицу как
    /// [`TableRef`]. До этого не создаётся ни ссылки на таблицу или строку, ни `bool`: только сырые указатели и байты.
    fn table(&mut self) -> TableRef<'_> {
        let head = self.head();
        let t = head.as_ptr();
        // SAFETY: по контракту `TableMemory` `t` указывает на заголовок, за которым в том же записываемом выделении
        // подряд лежат `NumEntries` строк с `Table[0]`; `&mut self` исключает другие доступы к этой памяти. Читаются
        // только `NumEntries` (u32) и байты BOOLEAN (u8), пишутся только байты BOOLEAN; ссылок не создаётся.
        unsafe {
            let n = usize::try_from((*t).NumEntries).unwrap_or(0);
            let rows = (&raw mut (*t).Table).cast::<MIB_IPFORWARD_ROW2>();
            for i in 0..n {
                canonical_booleans!(rows.add(i));
            }
        }
        TableRef {
            head,
            _owner: PhantomData,
        }
    }
}

impl TableMemory for MibTable {
    fn head(&mut self) -> NonNull<MIB_IPFORWARD_TABLE2> {
        self.0
    }
}

/// Заимствованная таблица маршрутов. Инвариант: заголовок `MIB_IPFORWARD_TABLE2`, за которым в том же выделении подряд
/// лежат `NumEntries` строк с `Table[0]` (`windows-sys` объявляет `Table` массивом из одной строки); все байты BOOLEAN
/// этих строк равны 0 или 1; не переживает заимствование владельца. Строится только здесь: [`TableMemory::table`]
/// (приводит байты BOOLEAN) и в тестах `synthetic` над типизированными строками (их `bool` равны 0/1 по типу).
#[derive(Clone, Copy)]
pub(super) struct TableRef<'a> {
    head: NonNull<MIB_IPFORWARD_TABLE2>,
    _owner: PhantomData<&'a MIB_IPFORWARD_TABLE2>,
}

/// Строки таблицы по порядку через `decode`: `NumEntries` строк одним срезом с `Table[0]`. ОС не вызывается, память
/// только читается.
pub(super) fn walk_table<T>(table: TableRef<'_>, decode: fn(&MIB_IPFORWARD_ROW2) -> T) -> Vec<T> {
    let head = table.head.as_ptr();
    // SAFETY: по инварианту `TableRef` `NumEntries` строк лежат подряд с `Table[0]` в том же выделении и их байты BOOLEAN
    // равны 0/1; остальные поля строки это целые и объединения целых, так что каждая строка допустима как
    // `MIB_IPFORWARD_ROW2`; срез не переживает заимствование `'_`.
    let rows = unsafe {
        let n = usize::try_from((*head).NumEntries).unwrap_or(0);
        std::slice::from_raw_parts((&raw const (*head).Table).cast::<MIB_IPFORWARD_ROW2>(), n)
    };
    rows.iter().map(decode).collect()
}

/// `MIB_IPFORWARD_TABLE2` with `N` typed rows: the header, then the rows from `Table[0]`.
#[cfg(test)]
#[repr(C)]
pub(super) struct SyntheticTable<const N: usize> {
    pub(super) num_entries: u32,
    pub(super) rows: [MIB_IPFORWARD_ROW2; N],
}

#[cfg(test)]
const _: () = assert!(
    std::mem::offset_of!(SyntheticTable<3>, rows)
        == std::mem::offset_of!(MIB_IPFORWARD_TABLE2, Table)
);

/// A borrowed table over typed rows (their `bool`s are 0/1 by type); `num_entries` never exceeds the rows the buffer
/// holds.
#[cfg(test)]
pub(super) fn synthetic<const N: usize>(t: &SyntheticTable<N>) -> TableRef<'_> {
    assert!(usize::try_from(t.num_entries).is_ok_and(|n| n <= t.rows.len()));
    TableRef {
        head: NonNull::from(t).cast(),
        _owner: PhantomData,
    }
}

/// Table memory built from raw bytes, aligned to 8 like `MIB_IPFORWARD_TABLE2`: rows are composed byte by byte, so a
/// BOOLEAN byte can hold any value without a typed `bool` ever existing.
#[cfg(test)]
pub(super) struct RawTable(Vec<u64>);

#[cfg(test)]
impl RawTable {
    /// The header and rows as bytes; they must hold the header and `NumEntries` rows (checked here).
    pub(super) fn new(bytes: &[u8]) -> RawTable {
        let n = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
        let need = std::mem::offset_of!(MIB_IPFORWARD_TABLE2, Table)
            + usize::try_from(n).unwrap() * size_of::<MIB_IPFORWARD_ROW2>();
        assert!(bytes.len() >= need.max(size_of::<MIB_IPFORWARD_TABLE2>()));
        let words = bytes
            .chunks(8)
            .map(|c| {
                let mut w = [0u8; 8];
                w[..c.len()].copy_from_slice(c);
                u64::from_ne_bytes(w)
            })
            .collect();
        RawTable(words)
    }

    /// The memory as bytes (padded with zeros to a multiple of 8).
    pub(super) fn bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(|w| w.to_ne_bytes()).collect()
    }
}

#[cfg(test)]
impl TableMemory for RawTable {
    fn head(&mut self) -> NonNull<MIB_IPFORWARD_TABLE2> {
        NonNull::from(self.0.as_mut_slice()).cast()
    }
}
