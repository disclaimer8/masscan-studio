use studio_platform::win_setup::command_line;
#[test]
fn argv_encoding_refuses_nul_and_preserves_quotes_and_trailing_backslashes() {
    assert!(command_line(&["x\0y"]).is_err());
    assert_eq!(
        command_line(&["", "abc", "a b", "x\"y", "end\\"]).unwrap(),
        "\"\" \"abc\" \"a b\" \"x\\\"y\" \"end\\\\\""
    );
}

#[cfg(windows)]
#[test]
fn encoded_uac_identity_round_trips_through_the_native_parser() {
    use windows_sys::Win32::{Foundation::LocalFree, UI::Shell::CommandLineToArgvW};
    let args = [
        "runner.exe",
        "",
        r#"{"executable":"C:\\a b\\x.exe","sid":"S-1-5-21"}"#,
        "end\\",
        "quote\"\\\"",
        "юзер 雪",
    ];
    let line: Vec<_> = command_line(&args)
        .unwrap()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut count = 0;
    // SAFETY: terminated UTF-16 input and writable count; successful allocation
    // contains count pointers to terminated strings and is released with LocalFree.
    let parsed = unsafe { CommandLineToArgvW(line.as_ptr(), &mut count) };
    assert!(!parsed.is_null());
    let mut actual = Vec::new();
    for i in 0..count as usize {
        // SAFETY: i is bounded by the OS-returned allocation count.
        let ptr = unsafe { *parsed.add(i) };
        let mut n = 0;
        // SAFETY: OS-owned result strings are terminated and allocation is live.
        unsafe {
            while *ptr.add(n) != 0 {
                n += 1;
            }
            actual.push(String::from_utf16(std::slice::from_raw_parts(ptr, n)).unwrap());
        }
    }
    // SAFETY: releases the unique API allocation after copying its strings.
    unsafe {
        LocalFree(parsed.cast());
    }
    assert_eq!(actual, args);
}
