//! Разбор SMB1 / SMB2 / NetBIOS Session Service (`src/proto-smb.c`, подэтап 4d):
//! - NetBIOS framing (`0x00` Session Message, `0x81`..`0x85`), на `0x82` (Positive Session Response) шлёт
//!   [`SMB1_HELLO`], на `0x83` печатает код ошибки NetBIOS.
//! - SMB1 (`0xFF "SMB"`): Negotiate (`0x72`) печатает `time=... TZ=...` и при отсутствии extended security
//!   (или при `ChallengeLength > 0`) домен и имя, шлёт null-session setup (`SMB1_NULL_SESSION_SETUP_EX` при
//!   `flags2 & 0x0800`, иначе `SMB1_NULL_SESSION_SETUP` с подстановкой `SessionKey`); SessionSetup (`0x73`)
//!   разбирает SPNEGO/NTLMSSP и строки `os=`, `ver=`, `domain=`, после чего закрывает соединение (`Close`).
//! - SMB2 (`0xFE "SMB"`): Negotiate (`opcode == 0`) печатает `guid=`, `time=`, `boottime=`, при `seqno == 0`
//!   шлёт [`SMB2_NEGOTIATE_REQUEST`], при `seqno == 1` шлёт [`SMB2_NULL_SESSION_SETUP`]; SessionSetup
//!   (`opcode == 1`) разбирает SPNEGO/NTLMSSP security blob и закрывает соединение (`Close`).
//!
//! Безопасная и независимая от нарезки (Р2, Р13) реализация без `unsafe`:
//! - Без C-таблицы `params[]` с переполнением буфера на команде `0xFF` (`proto-smb.c:241-285`) и без UB
//!   сдвига `u8 << 24` на `int`.
//! - Без `usize` underflow в `param_length - param_offset`, `byte_count - byte_offset`,
//!   `struct_length - offset`.
//! - Нулевые секции (`word_count == 0`, `byte_count == 0`, `struct_length == 2`, `nbt_length == 0`,
//!   `blob_offset == 0`, `blob_length == 0`) переходят в следующее состояние немедленно, поэтому результат и
//!   действия идентичны целиком, побайтово и в любой нарезке (Р13).

use crate::app::app_id;

use super::session::{ParseCx, Parser};
use super::spnego::Spnego;

/// `smb0_hello_template` (`src/proto-smb.c:1862-1872`): NetBIOS Session Request на порт 139, 72 байта.
pub(crate) const SMB0_HELLO: &[u8] = &[
    0x81, 0x00, 0x00, 0x44, 0x20, 0x43, 0x4b, 0x46, 0x44, 0x45, 0x4e, 0x45, 0x43, 0x46, 0x44, 0x45,
    0x46, 0x46, 0x43, 0x46, 0x47, 0x45, 0x46, 0x46, 0x43, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
    0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x20, 0x45, 0x44, 0x46, 0x43, 0x45, 0x46, 0x45, 0x46, 0x45,
    0x44, 0x45, 0x49, 0x45, 0x46, 0x46, 0x43, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
    0x41, 0x43, 0x41, 0x43, 0x41, 0x41, 0x41, 0x00,
];

/// `smb1_hello_template` (`src/proto-smb.c:96-109`): SMB1 Negotiate на порт 445 (и после NBT `0x82`), 73 байта.
pub(crate) const SMB1_HELLO: &[u8] = &[
    0x00, 0x00, 0x00, 0x45, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x22, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e,
    0x31, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00, 0x02, 0x53,
    0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00,
];

/// `smb1_hello_template_v1` (`src/proto-smb.c:111-124`, `--hello smbv1`): в C `8e6b3b0` идентичен `SMB1_HELLO`.
pub(crate) const SMB1_HELLO_V1: &[u8] = SMB1_HELLO;

/// `smb1_null_session_setup` (`src/proto-smb.c:132-150`): 134 байта; байты `0x2f..0x33` — LE `SessionKey`.
pub(crate) const SMB1_NULL_SESSION_SETUP: &[u8] = &[
    0x00, 0x00, 0x00, 0x7e, 0xff, 0x53, 0x4d, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
    0xff, 0xff, 0x01, 0x00, 0x0d, 0xff, 0x00, 0x00, 0x00, 0x04, 0x41, 0x32, 0x00, 0xef, 0x00, 0x53,
    0x45, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0xc0, 0x80, 0x00, 0x41,
    0x00, 0x00, 0x47, 0x00, 0x55, 0x00, 0x45, 0x00, 0x53, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4d, 0x00, 0x61, 0x00, 0x63, 0x00, 0x20, 0x00, 0x4f, 0x00, 0x53, 0x00, 0x20, 0x00, 0x58, 0x00,
    0x20, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2e, 0x00, 0x31, 0x00, 0x33, 0x00, 0x00, 0x00, 0x53, 0x00,
    0x4d, 0x00, 0x42, 0x00, 0x46, 0x00, 0x53, 0x00, 0x20, 0x00, 0x33, 0x00, 0x2e, 0x00, 0x32, 0x00,
    0x00, 0x00,
];

/// `smb1_null_session_setup_ex` (`src/proto-smb.c:152-177`): 188 байт (extended security / SPNEGO NTLMSSP).
pub(crate) const SMB1_NULL_SESSION_SETUP_EX: &[u8] = &[
    0x00, 0x00, 0x00, 0xb8, 0xff, 0x53, 0x4d, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x0c, 0xff, 0x00, 0x00, 0x00, 0x04, 0x41, 0x32, 0x00, 0xf1, 0x00, 0xa5,
    0x12, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0xc0, 0x80, 0x80, 0x7d, 0x00, 0x60,
    0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e, 0x30,
    0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x2a, 0x04,
    0x28, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x02, 0x88,
    0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x06, 0x01, 0xb0, 0x1d, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x00, 0x61, 0x00, 0x63, 0x00,
    0x20, 0x00, 0x4f, 0x00, 0x53, 0x00, 0x20, 0x00, 0x58, 0x00, 0x20, 0x00, 0x31, 0x00, 0x30, 0x00,
    0x2e, 0x00, 0x31, 0x00, 0x33, 0x00, 0x00, 0x00, 0x53, 0x00, 0x4d, 0x00, 0x42, 0x00, 0x46, 0x00,
    0x53, 0x00, 0x20, 0x00, 0x33, 0x00, 0x2e, 0x00, 0x32, 0x00, 0x00, 0x00,
];

/// `smb2_negotiate_request` (`src/proto-smb.c:179-194`): 112 байт.
pub(crate) const SMB2_NEGOTIATE_REQUEST: &[u8] = &[
    0x00, 0x00, 0x00, 0x6c, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x00,
    0x17, 0x97, 0x90, 0x40, 0xcd, 0xf0, 0x5e, 0x31, 0x8d, 0xea, 0xef, 0x98, 0xcd, 0xa5, 0x08, 0xda,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03,
];

/// `smb2_null_session_setup` (`src/proto-smb.c:195-217`): 166 байт.
pub(crate) const SMB2_NULL_SESSION_SETUP: &[u8] = &[
    0x00, 0x00, 0x00, 0xa2, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x58, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x48, 0x06, 0x06,
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x2a, 0x04, 0x28, 0x4e, 0x54,
    0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x88, 0x62, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01,
    0xb0, 0x1d, 0x0f, 0x00, 0x00, 0x00,
];

/// Форматирует Windows FILETIME (100-нс тики с 1601-01-01 UTC) в `"YYYY-MM-DD HH:MM:SS"` (UTC).
/// Алгоритм Howard Hinnant `civil_from_days`, без `unsafe` и `libc`.
fn format_windows_time(filetime: u64) -> String {
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let unix_secs = (filetime / 10_000_000) as i64 - EPOCH_DIFF_SECS;
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let hour = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;

    // Civil date from days since 1970-01-01 (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
}

/// Состояние верхнего уровня NBT framing (`smb_parse_record`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum NbtState {
    #[default]
    Type,
    Flags,
    Len1,
    Len2,
    Err,
    Smb,
    Drain,
    Unknown,
}

/// Состояние разбора одного SMB-сообщения внутри NBT `0x00` (`smb_parse_smb`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SmbState {
    #[default]
    Ver,
    Smb1Ver(u8), // 0='S', 1='M', 2='B'
    Smb1Hdr(u8), // 0..28: Cmd(0), Status(1..4), Flags1(5), Flags2(6..7), Pid/Sig/Rsvd/Tid/Uid/Mid(8..27), WordCount(28)
    Smb1Params,
    Smb1ByteCount1,
    Smb1ByteCount2,
    Smb1Data,
    Smb1DataAfter,
    Smb2Ver(u8), // 0='S', 1='M', 2='B'
    Smb2HdrLen1,
    Smb2HdrLen2,
    Smb2Header,
    Smb2StructLen1,
    Smb2StructLen2,
    Smb2Struct,
    Smb2UntilBlob,
    Smb2Blob,
    Smb2Remainder,
    Error,
}

/// Состояние разбора данных SMB1 Negotiate1 (`0x72` без extended security или с challenge).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Negot1State {
    #[default]
    Challenge,
    DomainU1,
    DomainU2,
    Domain1,
    Domain2,
    NameU1,
    NameU2,
    Name1,
    Name2,
    DomainAPre,
    DomainA,
    NameAPre,
    NameA,
    End,
}

/// Состояние разбора данных SMB1 SessionSetup (`0x73`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SetupState {
    #[default]
    Blob,
    Padding,
    OsA1,
    OsA2,
    VerA1,
    VerA2,
    DomainA1,
    DomainA2,
    OsU1,
    OsU2,
    OsU3,
    OsU4,
    VerU1,
    VerU2,
    VerU3,
    VerU4,
    DomainU1,
    DomainU2,
    DomainU3,
    DomainU4,
    Done,
}

#[derive(Debug, Default)]
struct Smb1Hdr {
    command: u8,
    flags2: u16,
    param_length: u16,
    param_offset: u16,
    byte_count: u16,
    byte_offset: u16,
    unicode_char: u16,
    // Negotiate (0x72) params
    session_key: u32,
    system_time: u64,
    server_tz: u16,
    challenge_len: u8,
    // Setup (0x73) params
    blob_length: u16,
    blob_offset: u16,
    blob_inited: bool,
    // Fixed once at end of params so chunk boundaries cannot flip negotiate1/negotiate2 (R13)
    use_negot2: bool,
    use_setup2: bool,
    // Data sub-states
    negot1: Negot1State,
    setup: SetupState,
}

#[derive(Debug, Default)]
struct Smb2Hdr {
    header_length: u16,
    struct_length: u16,
    offset: u16,
    opcode: u16,
    seqno: u64,
    blob_offset: u16,
    blob_length: u16,
    hdr_idx: u16,
    struct_idx: u16,
    guid_acc: u32,
    current_time: u64,
    boot_time: u64,
    hdr_error: bool,
}

/// Потоковый парсер SMB1 / SMB2 / NetBIOS (`AppProto::Smb`).
#[derive(Debug, Default)]
pub(crate) struct Smb {
    nbt_state: NbtState,
    nbt_type: u8,
    nbt_length: u32,
    smb_state: SmbState,
    is_printed_ver: bool,
    is_printed_time: bool,
    is_printed_guid: bool,
    is_printed_boottime: bool,
    smb1: Smb1Hdr,
    smb2: Smb2Hdr,
    spnego: Spnego,
}

impl Parser for Smb {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut i = 0;
        while i < px.len() {
            match self.nbt_state {
                NbtState::Type => {
                    self.spnego.clear_ntlmssp();
                    self.nbt_type = px[i];
                    i += 1;
                    self.nbt_state = NbtState::Flags;
                }
                NbtState::Flags => {
                    self.nbt_length = u32::from(px[i] & 0x01);
                    i += 1;
                    self.nbt_state = NbtState::Len1;
                }
                NbtState::Len1 => {
                    self.nbt_length = (self.nbt_length << 8) | u32::from(px[i]);
                    i += 1;
                    self.nbt_state = NbtState::Len2;
                }
                NbtState::Len2 => {
                    self.nbt_length = (self.nbt_length << 8) | u32::from(px[i]);
                    i += 1;
                    match self.nbt_type {
                        0x00 => {
                            self.smb_state = SmbState::Ver;
                            self.nbt_state = if self.nbt_length == 0 {
                                NbtState::Type
                            } else {
                                NbtState::Smb
                            };
                        }
                        0x81 => {
                            cx.append(app_id::SMB, b" PARSERR(nbt-sess) ");
                            self.nbt_state = NbtState::Unknown;
                        }
                        0x82 => {
                            cx.send(SMB1_HELLO);
                            self.nbt_state = if self.nbt_length == 0 {
                                NbtState::Type
                            } else {
                                NbtState::Drain
                            };
                        }
                        0x85 => {
                            self.nbt_state = if self.nbt_length == 0 {
                                NbtState::Type
                            } else {
                                NbtState::Drain
                            };
                        }
                        0x83 => {
                            self.nbt_state = NbtState::Err;
                        }
                        0x84 => {
                            cx.append(app_id::SMB, b" PARSERR(nbt-retarget) ");
                            self.nbt_state = NbtState::Unknown;
                        }
                        _ => {
                            cx.append(app_id::SMB, b"ERR unknown response");
                            self.nbt_state = NbtState::Err;
                        }
                    }
                }
                NbtState::Err => {
                    let err_msg: &[u8] = match px[i] {
                        0x80 => b"ERROR(Not listening on called name)",
                        0x81 => b"ERROR(Not listening for calling name)",
                        0x82 => b"ERROR(Called name not present)",
                        0x83 => b"ERROR(Called name present, but insufficient resources)",
                        0x8f => b"ERROR(Unspecified error)",
                        _ => b"ERROR(UNKNOWN)",
                    };
                    cx.append(app_id::SMB, err_msg);
                    i += 1;
                    // In C (`proto-smb.c:1758-1788`), NBT_ERR consumes 1 byte without decrementing
                    // nbt_length, then enters NBT_DRAIN. To stay chunk-independent when nbt_length==0:
                    self.nbt_state = if self.nbt_length == 0 {
                        NbtState::Type
                    } else {
                        NbtState::Drain
                    };
                }
                NbtState::Smb => {
                    let avail = (px.len() - i).min(self.nbt_length as usize);
                    self.parse_smb(cx, &px[i..i + avail]);
                    self.nbt_length -= avail as u32;
                    i += avail;
                    if self.nbt_length == 0 {
                        self.nbt_state = NbtState::Type;
                    }
                }
                NbtState::Drain => {
                    let skip = (px.len() - i).min(self.nbt_length as usize);
                    self.nbt_length -= skip as u32;
                    i += skip;
                    if self.nbt_length == 0 {
                        self.nbt_state = NbtState::Type;
                    }
                }
                NbtState::Unknown => {
                    return;
                }
            }
        }
    }
}

impl Smb {
    /// Разбирает `slice` байт внутри NBT Session Message (`0x00`), длина `slice` уже ограничена `nbt_length`.
    fn parse_smb(&mut self, cx: &mut ParseCx<'_>, slice: &[u8]) {
        let mut i = 0;
        while i < slice.len() {
            match self.smb_state {
                SmbState::Ver => {
                    let b = slice[i];
                    i += 1;
                    match b {
                        0xff => {
                            if !self.is_printed_ver {
                                cx.append(app_id::SMB, b"SMBv1 ");
                                self.is_printed_ver = true;
                            }
                            self.smb_state = SmbState::Smb1Ver(0);
                        }
                        0xfe => {
                            if !self.is_printed_ver {
                                cx.append(app_id::SMB, b"SMBv2 ");
                                self.is_printed_ver = true;
                            }
                            self.smb_state = SmbState::Smb2Ver(0);
                        }
                        _ => {
                            if !self.is_printed_ver {
                                cx.append(app_id::SMB, b"SMBv? ");
                                self.is_printed_ver = true;
                            }
                            self.smb_state = SmbState::Error;
                        }
                    }
                }
                SmbState::Smb1Ver(step) => {
                    let want = b"SMB"[usize::from(step)];
                    let b = slice[i];
                    i += 1;
                    if b != want {
                        self.smb_state = SmbState::Error;
                    } else if step == 2 {
                        self.smb1 = Smb1Hdr::default();
                        self.smb_state = SmbState::Smb1Hdr(0);
                    } else {
                        self.smb_state = SmbState::Smb1Ver(step + 1);
                    }
                }
                SmbState::Smb1Hdr(pos) => {
                    let b = slice[i];
                    i += 1;
                    match pos {
                        0 => self.smb1.command = b,
                        6 => self.smb1.flags2 = u16::from(b),
                        7 => self.smb1.flags2 |= u16::from(b) << 8,
                        28 => {
                            self.smb1.param_length = u16::from(b) * 2;
                            self.smb1.param_offset = 0;
                            self.smb_state = SmbState::Smb1Params;
                            continue;
                        }
                        _ => {}
                    }
                    self.smb_state = SmbState::Smb1Hdr(pos + 1);
                }
                SmbState::Smb1Params => {
                    if self.smb1.param_offset >= self.smb1.param_length {
                        self.finish_smb1_params(cx);
                        continue;
                    }
                    let rem = usize::from(self.smb1.param_length - self.smb1.param_offset);
                    let take = (slice.len() - i).min(rem);
                    for &b in &slice[i..i + take] {
                        let off = self.smb1.param_offset;
                        self.feed_smb1_param_byte(off, b);
                        self.smb1.param_offset += 1;
                    }
                    i += take;
                    if self.smb1.param_offset >= self.smb1.param_length {
                        self.finish_smb1_params(cx);
                    }
                }
                SmbState::Smb1ByteCount1 => {
                    self.smb1.byte_count = u16::from(slice[i]);
                    i += 1;
                    self.smb_state = SmbState::Smb1ByteCount2;
                }
                SmbState::Smb1ByteCount2 => {
                    self.smb1.byte_count |= u16::from(slice[i]) << 8;
                    self.smb1.byte_offset = 0;
                    i += 1;
                    self.smb_state = SmbState::Smb1Data;
                    if self.smb1.byte_count == 0 {
                        self.finish_smb1_data(cx);
                    }
                }
                SmbState::Smb1Data => {
                    let rem = usize::from(self.smb1.byte_count - self.smb1.byte_offset);
                    let take = (slice.len() - i).min(rem);
                    self.feed_smb1_data(cx, &slice[i..i + take]);
                    self.smb1.byte_offset += take as u16;
                    i += take;
                    if self.smb1.byte_offset >= self.smb1.byte_count {
                        self.finish_smb1_data(cx);
                    }
                }
                SmbState::Smb1DataAfter | SmbState::Smb2Remainder | SmbState::Error => {
                    // Поглощаем остаток NBT-кадра.
                    return;
                }
                SmbState::Smb2Ver(step) => {
                    let want = b"SMB"[usize::from(step)];
                    let b = slice[i];
                    i += 1;
                    if b != want {
                        self.smb_state = SmbState::Error;
                    } else if step == 2 {
                        self.smb2 = Smb2Hdr::default();
                        self.smb_state = SmbState::Smb2HdrLen1;
                    } else {
                        self.smb_state = SmbState::Smb2Ver(step + 1);
                    }
                }
                SmbState::Smb2HdrLen1 => {
                    self.smb2.header_length = u16::from(slice[i]);
                    i += 1;
                    self.smb_state = SmbState::Smb2HdrLen2;
                }
                SmbState::Smb2HdrLen2 => {
                    self.smb2.header_length |= u16::from(slice[i]) << 8;
                    i += 1;
                    if self.smb2.header_length < 12 {
                        cx.append(app_id::SMB, b" PARSERROR[hdrlen] ");
                        self.smb_state = SmbState::Error;
                    } else {
                        self.smb2.offset = 6;
                        self.smb2.hdr_idx = 0;
                        self.smb_state = SmbState::Smb2Header;
                    }
                }
                SmbState::Smb2Header => {
                    let rem = usize::from(self.smb2.header_length - self.smb2.offset);
                    let take = (slice.len() - i).min(rem);
                    for &b in &slice[i..i + take] {
                        self.feed_smb2_hdr_byte(cx, b);
                        self.smb2.offset += 1;
                    }
                    i += take;
                    if self.smb2.offset >= self.smb2.header_length {
                        self.smb_state = SmbState::Smb2StructLen1;
                    }
                }
                SmbState::Smb2StructLen1 => {
                    self.smb2.struct_length = u16::from(slice[i]);
                    i += 1;
                    self.smb_state = SmbState::Smb2StructLen2;
                }
                SmbState::Smb2StructLen2 => {
                    self.smb2.struct_length |= u16::from(slice[i]) << 8;
                    self.smb2.struct_length &= 0xfffe;
                    self.smb2.struct_idx = 0;
                    self.smb2.offset = 2;
                    self.smb2.current_time = 0;
                    self.smb2.boot_time = 0;
                    i += 1;
                    if self.smb2.struct_length < 2 {
                        cx.append(app_id::SMB, b" PARSERROR[structlen] ");
                        self.smb_state = SmbState::Error;
                    } else {
                        self.smb_state = SmbState::Smb2Struct;
                        if self.smb2.offset >= self.smb2.struct_length {
                            self.finish_smb2_struct(cx);
                        }
                    }
                }
                SmbState::Smb2Struct => {
                    let rem = usize::from(self.smb2.struct_length - self.smb2.offset);
                    let take = (slice.len() - i).min(rem);
                    for &b in &slice[i..i + take] {
                        match self.smb2.opcode {
                            0x00 => self.feed_smb2_negotiate_byte(cx, b),
                            0x01 => self.feed_smb2_setup_byte(b),
                            _ => {}
                        }
                        self.smb2.offset += 1;
                    }
                    i += take;
                    if self.smb2.offset >= self.smb2.struct_length {
                        self.finish_smb2_struct(cx);
                    }
                }
                SmbState::Smb2UntilBlob => {
                    let skip = (slice.len() - i).min(usize::from(self.smb2.blob_offset));
                    self.smb2.blob_offset -= skip as u16;
                    i += skip;
                    if self.smb2.blob_offset == 0 {
                        self.spnego.init(usize::from(self.smb2.blob_length));
                        self.smb_state = SmbState::Smb2Blob;
                        if self.smb2.blob_length == 0 {
                            self.finish_smb2_blob(cx);
                        }
                    }
                }
                SmbState::Smb2Blob => {
                    let take = (slice.len() - i).min(usize::from(self.smb2.blob_length));
                    self.spnego.feed(cx, &slice[i..i + take]);
                    self.smb2.blob_length -= take as u16;
                    i += take;
                    if self.smb2.blob_length == 0 {
                        self.finish_smb2_blob(cx);
                    }
                }
            }
        }
    }

    /// Разбор одного байта параметров SMB1 (`0x72` Negotiate и `0x73` SessionSetup) по смещению `off`.
    fn feed_smb1_param_byte(&mut self, off: u16, b: u8) {
        match self.smb1.command {
            0x72 => match off {
                15..=18 => {
                    self.smb1.session_key |= u32::from(b) << ((off - 15) * 8);
                }
                23..=30 => {
                    self.smb1.system_time |= u64::from(b) << ((off - 23) * 8);
                }
                31..=32 => {
                    self.smb1.server_tz |= u16::from(b) << ((off - 31) * 8);
                }
                33 => {
                    self.smb1.challenge_len = b;
                }
                _ => {}
            },
            0x73 => {
                if matches!(off, 6..=7) {
                    self.smb1.blob_length |= u16::from(b) << ((off - 6) * 8);
                }
            }
            _ => {}
        }
    }

    /// Действия по завершении поля параметров SMB1 (`proto-smb.c:1435-1481`).
    fn finish_smb1_params(&mut self, cx: &mut ParseCx<'_>) {
        self.smb_state = SmbState::Smb1ByteCount1;
        self.smb1.negot1 = Negot1State::Challenge;
        self.smb1.setup = SetupState::Blob;
        self.smb1.blob_offset = 0;
        self.smb1.blob_inited = false;
        self.smb1.use_negot2 = (self.smb1.flags2 & 0x0800 != 0) && self.smb1.challenge_len == 0;
        self.smb1.use_setup2 = (self.smb1.flags2 & 0x0800 != 0) || self.smb1.blob_length != 0;
        match self.smb1.command {
            0x72 => {
                if !self.is_printed_time {
                    let t = format_windows_time(self.smb1.system_time);
                    cx.append(app_id::SMB, format!(" time={t}").as_bytes());
                    let tz = self.smb1.server_tz as i16;
                    cx.append(app_id::SMB, format!(" TZ={tz:+} ").as_bytes());
                    self.is_printed_time = true;
                }
                if self.smb1.flags2 & 0x0800 != 0 {
                    cx.send(SMB1_NULL_SESSION_SETUP_EX);
                } else if self.smb1.session_key != 0 {
                    let mut buf = SMB1_NULL_SESSION_SETUP.to_vec();
                    buf[0x2f..0x33].copy_from_slice(&self.smb1.session_key.to_le_bytes());
                    cx.send_copy(&buf);
                } else {
                    cx.send(SMB1_NULL_SESSION_SETUP);
                }
            }
            0x73 => {}
            _ => {
                cx.append(app_id::SMB, b" PARSERR(unknown-resonse) ");
            }
        }
    }

    /// Разбор поля данных SMB1 (`proto-smb.c:1492-1508`).
    fn feed_smb1_data(&mut self, cx: &mut ParseCx<'_>, data: &[u8]) {
        match self.smb1.command {
            0x72 => {
                if !self.smb1.use_negot2 {
                    self.feed_smb1_negotiate1(cx, data);
                }
            }
            0x73 => {
                if self.smb1.use_setup2 {
                    self.feed_smb1_setup2(cx, data);
                } else {
                    self.feed_smb1_setup1(cx, data);
                }
            }
            _ => {}
        }
    }

    fn finish_smb1_data(&mut self, cx: &mut ParseCx<'_>) {
        self.smb_state = SmbState::Smb1DataAfter;
        if self.smb1.command == 0x73 {
            cx.close();
        }
    }

    /// `smb1_parse_negotiate1` (`proto-smb.c:351-434`): пропускает `ChallengeLength` байт, затем читает
    /// `domain=` и `name=` (UTF-16LE при `flags2 & 0x8000`, иначе ASCII).
    fn feed_smb1_negotiate1(&mut self, cx: &mut ParseCx<'_>, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            if self.smb1.negot1 == Negot1State::Challenge {
                if self.smb1.challenge_len == 0 {
                    self.smb1.negot1 = if self.smb1.flags2 & 0x8000 != 0 {
                        Negot1State::DomainU1
                    } else {
                        Negot1State::DomainAPre
                    };
                    continue;
                }
                let skip = (data.len() - i).min(usize::from(self.smb1.challenge_len));
                self.smb1.challenge_len -= skip as u8;
                i += skip;
                continue;
            }
            let b = data[i];
            i += 1;
            match self.smb1.negot1 {
                Negot1State::Challenge => unreachable!(),
                Negot1State::DomainU1 => {
                    self.smb1.unicode_char = u16::from(b);
                    self.smb1.negot1 = Negot1State::DomainU2;
                }
                Negot1State::DomainU2 => {
                    self.smb1.unicode_char |= u16::from(b) << 8;
                    if self.smb1.unicode_char == 0 {
                        self.smb1.negot1 = Negot1State::NameU1;
                    } else {
                        cx.append(app_id::SMB, b" domain=");
                        cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                        self.smb1.negot1 = Negot1State::Domain1;
                    }
                }
                Negot1State::Domain1 => {
                    self.smb1.unicode_char = u16::from(b);
                    self.smb1.negot1 = Negot1State::Domain2;
                }
                Negot1State::Domain2 => {
                    self.smb1.unicode_char |= u16::from(b) << 8;
                    if self.smb1.unicode_char == 0 {
                        self.smb1.negot1 = Negot1State::NameU1;
                    } else {
                        cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                        self.smb1.negot1 = Negot1State::Domain1;
                    }
                }
                Negot1State::NameU1 => {
                    self.smb1.unicode_char = u16::from(b);
                    self.smb1.negot1 = Negot1State::NameU2;
                }
                Negot1State::NameU2 => {
                    self.smb1.unicode_char |= u16::from(b) << 8;
                    if self.smb1.unicode_char == 0 {
                        self.smb1.negot1 = Negot1State::End;
                    } else {
                        cx.append(app_id::SMB, b" name=");
                        cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                        self.smb1.negot1 = Negot1State::Name1;
                    }
                }
                Negot1State::Name1 => {
                    self.smb1.unicode_char = u16::from(b);
                    self.smb1.negot1 = Negot1State::Name2;
                }
                Negot1State::Name2 => {
                    self.smb1.unicode_char |= u16::from(b) << 8;
                    if self.smb1.unicode_char == 0 {
                        self.smb1.negot1 = Negot1State::End;
                    } else {
                        cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                        self.smb1.negot1 = Negot1State::Name1;
                    }
                }
                Negot1State::DomainAPre => {
                    if b == 0 {
                        self.smb1.negot1 = Negot1State::NameAPre;
                    } else {
                        cx.append(app_id::SMB, b" domain=");
                        cx.append(app_id::SMB, &[b]);
                        self.smb1.negot1 = Negot1State::DomainA;
                    }
                }
                Negot1State::DomainA => {
                    if b == 0 {
                        self.smb1.negot1 = Negot1State::NameAPre;
                    } else {
                        cx.append(app_id::SMB, &[b]);
                    }
                }
                Negot1State::NameAPre => {
                    if b == 0 {
                        self.smb1.negot1 = Negot1State::End;
                    } else {
                        cx.append(app_id::SMB, b" name=");
                        cx.append(app_id::SMB, &[b]);
                        self.smb1.negot1 = Negot1State::NameA;
                    }
                }
                Negot1State::NameA => {
                    if b == 0 {
                        self.smb1.negot1 = Negot1State::End;
                    } else {
                        cx.append(app_id::SMB, &[b]);
                    }
                }
                Negot1State::End => return,
            }
        }
    }

    /// `smb1_parse_setup1` (`proto-smb.c:477-610`): пропускает 1 байт `D_PADDING`, затем `os=`, `ver=`, `domain=`.
    fn feed_smb1_setup1(&mut self, cx: &mut ParseCx<'_>, data: &[u8]) {
        let mut i = 0;
        if self.smb1.setup == SetupState::Blob {
            self.smb1.setup = SetupState::Padding;
        }
        while i < data.len() {
            if self.smb1.setup == SetupState::Padding {
                // В setup1 первый байт потребляется как padding.
                i += 1;
                self.smb1.setup = if self.smb1.flags2 & 0x8000 != 0 {
                    SetupState::OsU1
                } else {
                    SetupState::OsA1
                };
                continue;
            }
            self.feed_smb1_setup_string_byte(cx, data[i]);
            i += 1;
        }
    }

    /// `smb1_parse_setup2` (`proto-smb.c:654-813`): разбирает `BlobLength` байт через SPNEGO, затем
    /// без пропуска байта (как в C `D_PADDING`/`D_PADDING2` с `offset--`) читает `os=`, `ver=`, `domain=`.
    fn feed_smb1_setup2(&mut self, cx: &mut ParseCx<'_>, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            if self.smb1.setup == SetupState::Blob {
                if !self.smb1.blob_inited {
                    self.spnego.init(usize::from(self.smb1.blob_length));
                    self.smb1.blob_inited = true;
                }
                let rem = usize::from(self.smb1.blob_length.saturating_sub(self.smb1.blob_offset));
                let take = (data.len() - i).min(rem);
                if take > 0 {
                    self.spnego.feed(cx, &data[i..i + take]);
                    self.smb1.blob_offset += take as u16;
                    i += take;
                }
                if self.smb1.blob_offset >= self.smb1.blob_length {
                    self.smb1.setup = if self.smb1.flags2 & 0x8000 != 0 {
                        SetupState::OsU1
                    } else {
                        SetupState::OsA1
                    };
                }
                continue;
            }
            self.feed_smb1_setup_string_byte(cx, data[i]);
            i += 1;
        }
    }

    /// Общий разбор трёх строк `os=`, `ver=`, `domain=` (ASCII или UTF-16LE) для `setup1` и `setup2`.
    fn feed_smb1_setup_string_byte(&mut self, cx: &mut ParseCx<'_>, b: u8) {
        match self.smb1.setup {
            SetupState::OsA1 => {
                if b == 0 {
                    self.smb1.setup = SetupState::VerA1;
                } else {
                    cx.append(app_id::SMB, b" os=");
                    cx.append(app_id::SMB, &[b]);
                    self.smb1.setup = SetupState::OsA2;
                }
            }
            SetupState::OsA2 => {
                if b == 0 {
                    self.smb1.setup = SetupState::VerA1;
                } else {
                    cx.append(app_id::SMB, &[b]);
                }
            }
            SetupState::VerA1 => {
                if b == 0 {
                    self.smb1.setup = SetupState::DomainA1;
                } else {
                    cx.append(app_id::SMB, b" ver=");
                    cx.append(app_id::SMB, &[b]);
                    self.smb1.setup = SetupState::VerA2;
                }
            }
            SetupState::VerA2 => {
                if b == 0 {
                    self.smb1.setup = SetupState::DomainA1;
                } else {
                    cx.append(app_id::SMB, &[b]);
                }
            }
            SetupState::DomainA1 => {
                if b == 0 {
                    self.smb1.setup = SetupState::Done;
                } else {
                    cx.append(app_id::SMB, b" domain=");
                    cx.append(app_id::SMB, &[b]);
                    self.smb1.setup = SetupState::DomainA2;
                }
            }
            SetupState::DomainA2 => {
                if b == 0 {
                    self.smb1.setup = SetupState::Done;
                } else {
                    cx.append(app_id::SMB, &[b]);
                }
            }
            SetupState::OsU1 => {
                self.smb1.unicode_char = u16::from(b);
                self.smb1.setup = SetupState::OsU2;
            }
            SetupState::OsU2 => {
                self.smb1.unicode_char |= u16::from(b) << 8;
                if self.smb1.unicode_char == 0 {
                    self.smb1.setup = SetupState::VerU1;
                } else {
                    cx.append(app_id::SMB, b" os=");
                    cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                    self.smb1.setup = SetupState::OsU3;
                }
            }
            SetupState::OsU3 => {
                self.smb1.unicode_char = u16::from(b);
                self.smb1.setup = SetupState::OsU4;
            }
            SetupState::OsU4 => {
                self.smb1.unicode_char |= u16::from(b) << 8;
                if self.smb1.unicode_char == 0 {
                    self.smb1.setup = SetupState::VerU1;
                } else {
                    cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                    self.smb1.setup = SetupState::OsU3;
                }
            }
            SetupState::VerU1 => {
                self.smb1.unicode_char = u16::from(b);
                self.smb1.setup = SetupState::VerU2;
            }
            SetupState::VerU2 => {
                self.smb1.unicode_char |= u16::from(b) << 8;
                if self.smb1.unicode_char == 0 {
                    self.smb1.setup = SetupState::DomainU1;
                } else {
                    cx.append(app_id::SMB, b" ver=");
                    cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                    self.smb1.setup = SetupState::VerU3;
                }
            }
            SetupState::VerU3 => {
                self.smb1.unicode_char = u16::from(b);
                self.smb1.setup = SetupState::VerU4;
            }
            SetupState::VerU4 => {
                self.smb1.unicode_char |= u16::from(b) << 8;
                if self.smb1.unicode_char == 0 {
                    self.smb1.setup = SetupState::DomainU1;
                } else {
                    cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                    self.smb1.setup = SetupState::VerU3;
                }
            }
            SetupState::DomainU1 => {
                self.smb1.unicode_char = u16::from(b);
                self.smb1.setup = SetupState::DomainU2;
            }
            SetupState::DomainU2 => {
                self.smb1.unicode_char |= u16::from(b) << 8;
                if self.smb1.unicode_char == 0 {
                    self.smb1.setup = SetupState::Done;
                } else {
                    cx.append(app_id::SMB, b" domain=");
                    cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                    self.smb1.setup = SetupState::DomainU3;
                }
            }
            SetupState::DomainU3 => {
                self.smb1.unicode_char = u16::from(b);
                self.smb1.setup = SetupState::DomainU4;
            }
            SetupState::DomainU4 => {
                self.smb1.unicode_char |= u16::from(b) << 8;
                if self.smb1.unicode_char == 0 {
                    self.smb1.setup = SetupState::Done;
                } else {
                    cx.append_unicode(app_id::SMB, u32::from(self.smb1.unicode_char));
                    self.smb1.setup = SetupState::DomainU3;
                }
            }
            SetupState::Blob | SetupState::Padding | SetupState::Done => {}
        }
    }

    /// `smb2_parse_header` (`proto-smb.c:1121-1236`), начиная с байта 6 заголовка SMB2.
    fn feed_smb2_hdr_byte(&mut self, cx: &mut ParseCx<'_>, b: u8) {
        if self.smb2.hdr_error {
            return;
        }
        let idx = self.smb2.hdr_idx;
        self.smb2.hdr_idx = self.smb2.hdr_idx.saturating_add(1);
        match idx {
            6 => self.smb2.opcode = u16::from(b),
            7 => self.smb2.opcode |= u16::from(b) << 8,
            10 => {
                if b & 1 == 0 {
                    cx.append(app_id::SMB, b" PARSERROR[flags] ");
                    self.smb2.hdr_error = true;
                }
            }
            18..=25 => {
                self.smb2.seqno |= u64::from(b) << (u32::from(idx - 18) * 8);
            }
            _ => {}
        }
    }

    /// `smb2_parse_negotiate` (`proto-smb.c:879-1055`), начиная с байта 2 структуры Negotiate Response.
    fn feed_smb2_negotiate_byte(&mut self, cx: &mut ParseCx<'_>, b: u8) {
        let idx = self.smb2.struct_idx;
        self.smb2.struct_idx = self.smb2.struct_idx.saturating_add(1);
        match idx {
            5 => {
                if !self.is_printed_guid {
                    cx.append(app_id::SMB, b" guid=");
                }
            }
            6 => self.smb2.guid_acc = u32::from(b),
            7..=9 => {
                self.smb2.guid_acc |= u32::from(b) << (u32::from(idx - 6) * 8);
                if idx == 9 && !self.is_printed_guid {
                    let s = format!("{:08x}-", self.smb2.guid_acc);
                    cx.append(app_id::SMB, s.as_bytes());
                }
            }
            10 | 12 => self.smb2.guid_acc = u32::from(b),
            11 | 13 => {
                self.smb2.guid_acc |= u32::from(b) << 8;
                if !self.is_printed_guid {
                    let s = format!("{:04x}-", self.smb2.guid_acc);
                    cx.append(app_id::SMB, s.as_bytes());
                }
            }
            15 => {
                if !self.is_printed_guid {
                    let s = format!("{b:02x}-");
                    cx.append(app_id::SMB, s.as_bytes());
                }
            }
            14 | 16..=21 => {
                if !self.is_printed_guid {
                    let s = format!("{b:02x}");
                    cx.append(app_id::SMB, s.as_bytes());
                }
                if idx == 21 {
                    self.is_printed_guid = true;
                }
            }
            38..=45 => {
                self.smb2.current_time |= u64::from(b) << (u32::from(idx - 38) * 8);
                if idx == 45 && !self.is_printed_time {
                    let t = format_windows_time(self.smb2.current_time);
                    cx.append(app_id::SMB, format!(" time={t} ").as_bytes());
                    self.is_printed_time = true;
                }
            }
            46..=53 => {
                self.smb2.boot_time |= u64::from(b) << (u32::from(idx - 46) * 8);
                if idx == 53 && !self.is_printed_boottime {
                    let t = format_windows_time(self.smb2.boot_time);
                    cx.append(app_id::SMB, format!(" boottime={t} ").as_bytes());
                    self.is_printed_boottime = true;
                }
            }
            54 => self.smb2.blob_offset = u16::from(b),
            55 => self.smb2.blob_offset |= u16::from(b) << 8,
            56 => self.smb2.blob_length = u16::from(b),
            57 => self.smb2.blob_length |= u16::from(b) << 8,
            _ => {}
        }
    }

    /// `smb2_parse_setup` (`proto-smb.c:1060-1114`), начиная с байта 2 структуры SessionSetup Response.
    fn feed_smb2_setup_byte(&mut self, b: u8) {
        let idx = self.smb2.struct_idx;
        self.smb2.struct_idx = self.smb2.struct_idx.saturating_add(1);
        match idx {
            2 => self.smb2.blob_offset = u16::from(b),
            3 => self.smb2.blob_offset |= u16::from(b) << 8,
            4 => self.smb2.blob_length = u16::from(b),
            5 => self.smb2.blob_length |= u16::from(b) << 8,
            _ => {}
        }
    }

    /// Завершение структуры SMB2: отправка следующего запроса и переход к security blob (`proto-smb.c:1589-1617`).
    fn finish_smb2_struct(&mut self, cx: &mut ParseCx<'_>) {
        if self.smb2.opcode == 0x00 {
            if self.smb2.seqno == 0 {
                cx.send(SMB2_NEGOTIATE_REQUEST);
            } else if self.smb2.seqno == 1 {
                cx.send(SMB2_NULL_SESSION_SETUP);
            }
        }
        let header_and_struct = self
            .smb2
            .header_length
            .saturating_add(self.smb2.struct_length);
        if self.smb2.blob_length == 0 || self.smb2.blob_offset < header_and_struct {
            self.smb_state = SmbState::Smb2Remainder;
        } else {
            self.smb2.blob_offset -= header_and_struct;
            if self.smb2.blob_offset == 0 {
                self.spnego.init(usize::from(self.smb2.blob_length));
                self.smb_state = SmbState::Smb2Blob;
            } else {
                self.smb_state = SmbState::Smb2UntilBlob;
            }
        }
    }

    fn finish_smb2_blob(&mut self, cx: &mut ParseCx<'_>) {
        self.smb_state = SmbState::Smb2Remainder;
        if self.smb2.opcode == 1 {
            cx.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banner1::driver::{StreamAction, banner_stream};
    use crate::banner1::hello::TcpBannerSettings;
    use crate::banner1::{TestRng, stream_in_splits};
    use rmasscan_core::banner::MAX_BANNER_BYTES;

    /// Вектор 1 из `smb_selftest` (`src/proto-smb.c:1930-1991`): EPSON Storage Server (SMB1 Negotiate + SessionSetup + SPNEGO/NTLMSSP).
    const C_SELFTEST_EPSON: &[u8] = &[
        0x00, 0x00, 0x00, 0x9f, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x88, 0x01,
        0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
        0x01, 0x00, 0xff, 0xff, 0x00, 0x00, 0x11, 0x00, 0x00, 0x03, 0x0a, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xad, 0xa0, 0x03, 0x0a, 0x7c, 0xe0, 0x00, 0x80,
        0x00, 0x1d, 0xbd, 0xd5, 0xe2, 0x0f, 0xcf, 0x01, 0x00, 0x00, 0x00, 0x5a, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60,
        0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e,
        0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa3,
        0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69,
        0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40,
        0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x00, 0x00,
        0x01, 0x2a, 0xff, 0x53, 0x4d, 0x42, 0x73, 0x16, 0x00, 0x00, 0xc0, 0x88, 0x01, 0xc0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x04, 0xff, 0x00, 0x2a, 0x01, 0x00, 0x00, 0xb3, 0x00, 0xff, 0x00,
        0xa1, 0x81, 0xb0, 0x30, 0x81, 0xad, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa1, 0x0c, 0x06, 0x0a,
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x81, 0x97, 0x04, 0x81,
        0x94, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x12, 0x00,
        0x12, 0x00, 0x30, 0x00, 0x00, 0x00, 0x31, 0x02, 0x89, 0xe0, 0x31, 0x6a, 0x74, 0x8f, 0xb5,
        0xf1, 0xe1, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x52, 0x00,
        0x42, 0x00, 0x00, 0x00, 0x57, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00, 0x47, 0x00, 0x52,
        0x00, 0x4f, 0x00, 0x55, 0x00, 0x50, 0x00, 0x02, 0x00, 0x12, 0x00, 0x57, 0x00, 0x4f, 0x00,
        0x52, 0x00, 0x4b, 0x00, 0x47, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x55, 0x00, 0x50, 0x00, 0x01,
        0x00, 0x16, 0x00, 0x45, 0x00, 0x50, 0x00, 0x53, 0x00, 0x4f, 0x00, 0x4e, 0x00, 0x38, 0x00,
        0x38, 0x00, 0x33, 0x00, 0x31, 0x00, 0x46, 0x00, 0x45, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x16, 0x00, 0x45, 0x00, 0x50, 0x00, 0x53, 0x00, 0x4f, 0x00, 0x4e, 0x00, 0x38, 0x00,
        0x38, 0x00, 0x33, 0x00, 0x31, 0x00, 0x46, 0x00, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45,
        0x00, 0x50, 0x00, 0x53, 0x00, 0x4f, 0x00, 0x4e, 0x00, 0x20, 0x00, 0x53, 0x00, 0x74, 0x00,
        0x6f, 0x00, 0x72, 0x00, 0x61, 0x00, 0x67, 0x00, 0x65, 0x00, 0x20, 0x00, 0x53, 0x00, 0x65,
        0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x51, 0x00,
        0x20, 0x00, 0x36, 0x00, 0x2e, 0x00, 0x32, 0x00, 0x00, 0x00, 0x57, 0x00, 0x4f, 0x00, 0x52,
        0x00, 0x4b, 0x00, 0x47, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x55, 0x00, 0x50, 0x00, 0x00, 0x00,
    ];

    /// Вектор 2 из `smb_selftest` (`src/proto-smb.c:1998-2011`): SMB1 Negotiate без extended security (`domain=S659C27D`).
    const C_SELFTEST_S659C27D: &[u8] = &[
        0x00, 0x00, 0x00, 0x56, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x98, 0x45,
        0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x93, 0x07, 0x00, 0x00, 0x01, 0x00, 0x11, 0x00, 0x00, 0x03, 0x05, 0x00, 0x01, 0x00, 0x04,
        0x11, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x1d, 0xc2, 0x00, 0x00,
        0x00, 0x83, 0xa9, 0xe2, 0x31, 0x02, 0xd4, 0x01, 0x00, 0x00, 0x08, 0x11, 0x00, 0x77, 0x6d,
        0x78, 0x8f, 0x06, 0x52, 0x8f, 0xb8, 0x53, 0x36, 0x35, 0x39, 0x43, 0x32, 0x37, 0x44, 0x00,
    ];

    /// Оба C selftest-вектора целиком, побайтово и в случайных нарезках (Р13) совпадают с C байт в байт.
    #[test]
    fn c_selftest_vectors_match_byte_for_byte_in_all_splits() {
        let r1 = stream_in_splits(445, None, C_SELFTEST_EPSON, 1);
        assert_eq!(r1.app_proto, Some(app_id::SMB));
        assert_eq!(
            r1.records,
            [(
                app_id::SMB,
                b"SMBv1  time=2014-01-12 22:08:34 TZ=+0  domain=WORKGROUP version=87.0.79 ntlm-ver=0 domain=WORKGROUP name=EPSON8831FE domain-dns= name-dns=EPSON8831FE os=EPSON Storage Server ver=NQ 6.2 domain=WORKGROUP".to_vec()
            )]
        );
        assert_eq!(
            r1.actions,
            [
                StreamAction::Send(SMB1_NULL_SESSION_SETUP_EX.to_vec()),
                StreamAction::Close,
            ]
        );

        let r2 = stream_in_splits(445, None, C_SELFTEST_S659C27D, 2);
        assert_eq!(r2.app_proto, Some(app_id::SMB));
        assert_eq!(
            r2.records,
            [(
                app_id::SMB,
                b"SMBv1  time=2018-06-12 09:43:58 TZ=+0  domain=S659C27D".to_vec()
            )]
        );
        let mut want_s659 = SMB1_NULL_SESSION_SETUP.to_vec();
        want_s659[0x2f..0x33].copy_from_slice(&0x0000_00a9u32.to_le_bytes());
        assert_eq!(r2.actions, [StreamAction::Send(want_s659)]);
    }

    /// SMB1 без extended security с нулевым и ненулевым SessionKey: патчит байты `0x2f..0x33` в `SMB1_NULL_SESSION_SETUP`.
    #[test]
    fn smb1_non_extended_patches_session_key() {
        let mut pkt = C_SELFTEST_S659C27D.to_vec();
        // Params start at offset 4 (NBT) + 32 (SMB1 hdr) + 1 (WordCount) = 37; SessionKey at +15 = 52..56.
        pkt[52..56].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let r = stream_in_splits(445, None, &pkt, 3);
        let mut want = SMB1_NULL_SESSION_SETUP.to_vec();
        want[0x2f..0x33].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        assert_eq!(r.actions, [StreamAction::Send(want)]);

        pkt[52..56].copy_from_slice(&0u32.to_le_bytes());
        let r0 = stream_in_splits(445, None, &pkt, 30);
        assert_eq!(
            r0.actions,
            [StreamAction::Send(SMB1_NULL_SESSION_SETUP.to_vec())]
        );
    }

    /// NBT `0x82` (Positive Session Response) на порту 139 шлёт `SMB1_HELLO` и разбирает следующий SMB-кадр;
    /// NBT `0x83` печатает ошибку NetBIOS.
    #[test]
    fn nbt_positive_and_negative_session_responses() {
        let mut stream = vec![0x82, 0x00, 0x00, 0x00];
        stream.extend_from_slice(C_SELFTEST_S659C27D);
        let r = stream_in_splits(139, None, &stream, 4);
        assert_eq!(r.app_proto, Some(app_id::SMB));
        let mut want_s659 = SMB1_NULL_SESSION_SETUP.to_vec();
        want_s659[0x2f..0x33].copy_from_slice(&0x0000_00a9u32.to_le_bytes());
        assert_eq!(
            r.actions,
            [
                StreamAction::Send(SMB1_HELLO.to_vec()),
                StreamAction::Send(want_s659),
            ]
        );
        assert_eq!(
            r.records,
            [(
                app_id::SMB,
                b"SMBv1  time=2018-06-12 09:43:58 TZ=+0  domain=S659C27D".to_vec()
            )]
        );

        let r_err = stream_in_splits(139, None, b"\x83\x00\x00\x01\x8f", 5);
        assert_eq!(r_err.app_proto, Some(app_id::SMB));
        assert_eq!(
            r_err.records,
            [(app_id::SMB, b"ERROR(Unspecified error)".to_vec())]
        );
        assert!(r_err.actions.is_empty());
    }

    /// SMB2 Negotiate (seqno 0 → SMB2_NEGOTIATE_REQUEST, seqno 1 → SMB2_NULL_SESSION_SETUP) + SessionSetup (SPNEGO/NTLMSSP → Close).
    #[test]
    fn smb2_negotiate_and_session_setup_with_ntlmssp() {
        // Build SMB2 Negotiate Response #1 (seqno=0) with GUID, current_time, boot_time.
        let mut neg0 = vec![0u8; 4 + 64 + 64];
        let body_len = (64 + 64) as u32;
        neg0[0..4].copy_from_slice(&body_len.to_be_bytes());
        neg0[4..8].copy_from_slice(b"\xfeSMB");
        neg0[8..10].copy_from_slice(&64u16.to_le_bytes()); // header_length
        neg0[16..18].copy_from_slice(&0u16.to_le_bytes()); // opcode = Negotiate
        neg0[20] = 0x01; // flags: response
        neg0[28..36].copy_from_slice(&0u64.to_le_bytes()); // seqno = 0
        // Struct (offset 68): struct_length = 65 (0x41 -> 64 fixed + dynamic)
        neg0[68..70].copy_from_slice(&65u16.to_le_bytes());
        // GUID at struct+8 (offset 76..92)
        neg0[76..92].copy_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ]);
        // CurrentTime at struct+40 (offset 108..116): 2014-01-12 22:08:34 UTC
        let ft_2014: u64 = (1_389_564_514u64 + 11_644_473_600) * 10_000_000;
        neg0[108..116].copy_from_slice(&ft_2014.to_le_bytes());
        // BootTime at struct+48 (offset 116..124): 2014-01-01 00:00:00 UTC
        let ft_boot: u64 = (1_388_534_400u64 + 11_644_473_600) * 10_000_000;
        neg0[116..124].copy_from_slice(&ft_boot.to_le_bytes());

        // Second Negotiate Response (seqno=1): GUID/time/boottime must NOT be printed twice.
        let mut neg1 = neg0.clone();
        neg1[28..36].copy_from_slice(&1u64.to_le_bytes());

        // SessionSetup Response (opcode=1) with SPNEGO -> NTLMSSP Type-2.
        let mut ntlm = vec![0u8; 56];
        ntlm[0..8].copy_from_slice(b"NTLMSSP\0");
        ntlm[8..12].copy_from_slice(&2u32.to_le_bytes());
        ntlm[48] = 10;
        ntlm[49] = 0;
        ntlm[50..52].copy_from_slice(&17763u16.to_le_bytes());
        ntlm[55] = 15;
        let mut blob = vec![0xa1, 64, 0x30, 62, 0xa2, 60, 0x04, 56];
        blob.extend_from_slice(&ntlm);

        let setup_body_len = (64 + 8 + blob.len()) as u32;
        let mut setup = vec![0u8; 4 + 64 + 8];
        setup[0..4].copy_from_slice(&setup_body_len.to_be_bytes());
        setup[4..8].copy_from_slice(b"\xfeSMB");
        setup[8..10].copy_from_slice(&64u16.to_le_bytes());
        setup[16..18].copy_from_slice(&1u16.to_le_bytes()); // opcode = SessionSetup
        setup[20] = 0x01; // response flag
        setup[28..36].copy_from_slice(&2u64.to_le_bytes());
        setup[68..70].copy_from_slice(&9u16.to_le_bytes()); // struct_length = 8 + dynamic
        setup[72..74].copy_from_slice(&72u16.to_le_bytes()); // blob_offset = 64 + 8
        setup[74..76].copy_from_slice(&(blob.len() as u16).to_le_bytes());
        setup.extend_from_slice(&blob);

        let stream = [neg0, neg1, setup].concat();
        let r = stream_in_splits(445, None, &stream, 6);
        assert_eq!(r.app_proto, Some(app_id::SMB));
        assert_eq!(
            r.records,
            [(
                app_id::SMB,
                b"SMBv2  guid=12345678-9abc-def0-1122-334455667788 time=2014-01-12 22:08:34  boottime=2014-01-01 00:00:00  version=10.0.17763 ntlm-ver=15".to_vec()
            )]
        );
        assert_eq!(
            r.actions,
            [
                StreamAction::Send(SMB2_NEGOTIATE_REQUEST.to_vec()),
                StreamAction::Send(SMB2_NULL_SESSION_SETUP.to_vec()),
                StreamAction::Close,
            ]
        );
    }

    /// Р2: C-краши (команда `0xFF`, `word_count = 255`, `struct_length = 0`, `hdr_len = 0`) безопасны и не зависят от нарезки.
    #[test]
    fn c_crash_inputs_are_safe() {
        // SMB1 command 0xFF (в C global-buffer-overflow в `smb_params_parse`)
        let mut cmd_ff = vec![0u8; 4 + 32 + 1 + 4 + 2];
        cmd_ff[3] = (cmd_ff.len() - 4) as u8;
        cmd_ff[4..8].copy_from_slice(b"\xffSMB");
        cmd_ff[8] = 0xff; // command = 0xFF
        cmd_ff[36] = 2; // word_count = 2 (4 bytes params)
        let r = stream_in_splits(445, Some(app_id::SMB), &cmd_ff, 7);
        assert_eq!(
            r.records,
            [(app_id::SMB, b"SMBv1  PARSERR(unknown-resonse) ".to_vec())]
        );

        // SMB2 bad hdrlen (< 12)
        let bad_hdr = b"\x00\x00\x00\x08\xfeSMB\x04\x00\x00\x00";
        let r = stream_in_splits(445, Some(app_id::SMB), bad_hdr, 8);
        assert_eq!(
            r.records,
            [(app_id::SMB, b"SMBv2  PARSERROR[hdrlen] ".to_vec())]
        );

        // SMB2 bad structlen (< 2)
        let mut bad_st = vec![0u8; 4 + 14];
        bad_st[3] = 14;
        bad_st[4..8].copy_from_slice(b"\xfeSMB");
        bad_st[8..10].copy_from_slice(&12u16.to_le_bytes());
        let r = stream_in_splits(445, Some(app_id::SMB), &bad_st, 9);
        assert_eq!(
            r.records,
            [(app_id::SMB, b"SMBv2  PARSERROR[structlen] ".to_vec())]
        );
    }

    /// Никогда не паникует и не зависит от нарезки на 4000 случайных/структурированных потоках SMB.
    #[test]
    fn smb_never_panics_and_is_split_invariant() {
        let seeds: [&[u8]; 3] = [
            C_SELFTEST_EPSON,
            C_SELFTEST_S659C27D,
            b"\x82\x00\x00\x00\x00\x00\x00\x0a\xfeSMB\x40\x00\x00\x00",
        ];
        let s = TcpBannerSettings::default();
        let mut rng = TestRng(0x5B4D_4234_DEAD_BEEF);
        for round in 0..2000 {
            let mut stream = if rng.below(3) == 0 {
                let len = rng.below(256);
                (0..len).map(|_| rng.next() as u8).collect::<Vec<u8>>()
            } else {
                let mut v = seeds[rng.below(seeds.len())].to_vec();
                for _ in 0..1 + rng.below(8) {
                    if !v.is_empty() {
                        let pos = rng.below(v.len());
                        v[pos] = rng.next() as u8;
                    }
                }
                if rng.below(4) == 0 && !v.is_empty() {
                    let cut = rng.below(v.len());
                    v.truncate(cut);
                }
                v
            };
            if stream.len() > 2048 {
                stream.truncate(2048);
            }
            let force = if rng.below(2) == 0 {
                Some(app_id::SMB)
            } else {
                None
            };
            let whole = banner_stream(&s, 445, force, &[&stream]);
            for (_, b) in &whole.records {
                assert!(
                    !b.is_empty() && b.len() <= MAX_BANNER_BYTES,
                    "round {round}"
                );
            }
            let mut cuts: Vec<usize> = (0..1 + rng.below(stream.len().min(16) + 1))
                .map(|_| rng.below(stream.len() + 1))
                .collect();
            cuts.sort_unstable();
            let mut segs = Vec::new();
            let mut at = 0;
            for c in cuts.into_iter().chain([stream.len()]) {
                segs.push(&stream[at..c]);
                at = c;
            }
            let split = banner_stream(&s, 445, force, &segs);
            assert_eq!(split.app_proto, whole.app_proto, "round {round}");
            assert_eq!(split.records, whole.records, "round {round}");
            if !matches!(whole.app_proto, Some(app_id::TELNET | app_id::MC)) {
                assert_eq!(split.actions, whole.actions, "round {round}");
            }
        }
    }
}
