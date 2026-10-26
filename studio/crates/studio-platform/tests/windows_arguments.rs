use studio_platform::win_setup::command_line;
#[test]
fn argv_encoding_refuses_nul_and_preserves_quotes_and_trailing_backslashes() {
    assert!(command_line(&["x\0y"]).is_err());
    assert_eq!(
        command_line(&["", "abc", "a b", "x\"y", "end\\"]).unwrap(),
        "\"\" \"abc\" \"a b\" \"x\\\"y\" \"end\\\\\""
    );
}
