//! SSH: `src/proto-ssh.c:52-178`, masscan 8e6b3b0, AGPL-3.0. Сырые байты, fallthrough KEX и ранний
//! переход к следующей длине сохранены; ERROR берёт ровно один следующий байт (E2.4).
use super::session::{ParseCx, Parser, c_isprint};
use crate::app_id;

#[derive(Default)]
pub(super) struct Ssh {
    state: u8,
    left: usize,
}

impl Parser for Ssh {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        for &c in px {
            if self.state == 32 {
                break;
            }
            cx.append(app_id::SSH2, &[c]);
            match self.state {
                0 => {
                    if c == b'\n' {
                        cx.send(b"SSH-2.0-OPENSSH_7.9\r\n");
                        self.left = 0;
                        self.state = 21;
                    }
                    if !c_isprint(c) && !matches!(c, b'\t'..=b'\r' | b' ') {
                        self.state = 31;
                        cx.close();
                    }
                }
                21 => {
                    self.left = usize::from(c) << 24;
                    self.state = 22;
                }
                22..=23 => {
                    self.left = self
                        .left
                        .wrapping_add(usize::from(c) << if self.state == 22 { 16 } else { 8 });
                    self.state += 1;
                }
                24 => {
                    self.left = self.left.wrapping_add(usize::from(c));
                    self.state = 10;
                }
                10 => {
                    self.left = self.left.wrapping_sub(1);
                    self.state = 11;
                }
                // `src/proto-ssh.c:126-149`: любой message code падает в KEX; этот байт посчитан дважды.
                11 => {
                    self.left = self.left.wrapping_sub(2);
                    cx.send(KEX);
                    self.state = 20;
                }
                20 => {
                    self.left = self.left.wrapping_sub(1);
                    if self.left == 0 {
                        self.state = 21;
                    }
                }
                _ => self.state = 32,
            }
        }
    }
    #[cfg(test)]
    fn probe(&self) -> u32 {
        u32::from(self.state)
    }
}

// `src/proto-ssh.c:10-41`: masscan-authored fixed KEXINIT + KEXDH_INIT, captured independently from C.
const KEX: &[u8; 1248] = b"\x00\x00\x04L\x04\x14\xf3\xca\xd2\x90\xec\xf4|GUL\x88\xcf:r+\xb2\x00\x00\x00\xd8diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256\x00\x00\x00!ssh-rsa,rsa-sha2-512,rsa-sha2-256\x00\x00\x00\xafchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc\x00\x00\x00\xafchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\xd5umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8c\x05\x1e\x00\x00\x00\x81\x00\xd4n\xe0\x12\xa6V\x957\xa0\x14.NMWH\x1dK\x80\x90\x1eao\x5c\xc4\xd7\xbc\x17%\xb7A\x8cl\x8b\xedt-\xc0T\xeb\x08:y^\x0c\xad\x04\xe8\xb7\xfb\xa1hbf\xd3\x9a&9\xaal\x89/\x5c\x99\xab\xd2C\xda\xa7\xef\x1c\x19\xdc\xa6\x03\xc9\x8aV\x19t\xd1\xb8\x08\xdcv\x14\xe7\x86Pt\x01\xed\xd4\xfb\x1a\x1a%]\x1a\xc7_\x0c\xb3\xccXZ@\xd5\x04\xa5\xc10\x14\x86\xf0\xb83\x17\xb4#\x9dCm8\x87\xec\xa9\xbc;\x00\x00\x00\x00\x00";
