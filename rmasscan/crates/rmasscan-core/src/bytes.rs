//! Чтения big-endian из недоверенных байт (AGPL-3.0). Каждое чтение проверяет границы и возвращает `None` за концом
//! буфера; «за концом это 0» остаётся только в `checksum.rs`, где его требует C.

/// `N` байт с позиции `i`; `None`, если их там нет (в том числе при `i` больше длины и `i == usize::MAX`).
pub(crate) fn array_at<const N: usize>(b: &[u8], i: usize) -> Option<[u8; N]> {
    b.get(i..)?.first_chunk::<N>().copied()
}

pub(crate) fn be16_at(b: &[u8], i: usize) -> Option<u16> {
    array_at(b, i).map(u16::from_be_bytes)
}

pub(crate) fn be32_at(b: &[u8], i: usize) -> Option<u32> {
    array_at(b, i).map(u32::from_be_bytes)
}

pub(crate) fn be128_at(b: &[u8], i: usize) -> Option<u128> {
    array_at(b, i).map(u128::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_return_none_past_the_end() {
        let data: Vec<u8> = (1..=16).collect();
        for len in 0..8usize {
            let b = &data[..len];
            for i in (0..10usize).chain([usize::MAX]) {
                let fits = |n: usize| i.checked_add(n).is_some_and(|e| e <= len);
                assert_eq!(be16_at(b, i).is_some(), fits(2), "be16 len {len} i {i}");
                assert_eq!(be32_at(b, i).is_some(), fits(4), "be32 len {len} i {i}");
                assert_eq!(be128_at(b, i).is_some(), fits(16), "be128 len {len} i {i}");
                assert_eq!(
                    array_at::<6>(b, i).is_some(),
                    fits(6),
                    "array len {len} i {i}"
                );
                assert_eq!(
                    array_at::<0>(b, i).is_some(),
                    i <= len,
                    "array0 len {len} i {i}"
                );
            }
        }
        let b = [0x12, 0x34, 0x56, 0x78, 0x9a];
        assert_eq!(be16_at(&b, 1), Some(0x3456));
        assert_eq!(be32_at(&b, 1), Some(0x3456_789a));
        assert_eq!(array_at::<2>(&b, 3), Some([0x78, 0x9a]));
        let w: Vec<u8> = (0..17).collect();
        assert_eq!(
            be128_at(&w, 1),
            Some(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10)
        );
    }
}
