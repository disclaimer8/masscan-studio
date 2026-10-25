use rmasscan_lab::oracle_util::patch_offline;
#[test]
fn patches_only_the_unique_offline_adapter_return() {
    let old = "    if (is_offline)\n        return adapter;\n";
    assert!(
        patch_offline(old)
            .unwrap()
            .contains("adapter->link_type = 1")
    );
    assert!(patch_offline("").is_err());
    assert!(patch_offline(&old.repeat(2)).is_err());
}
