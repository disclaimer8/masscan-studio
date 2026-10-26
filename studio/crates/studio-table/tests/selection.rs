use studio_table::{Row, Table};

fn table() -> Table {
    let mut table = Table::new(0);
    table.append_rows(
        [
            ("198.18.0.10", 80),
            ("198.18.0.2", 443),
            ("198.18.0.2", 80),
            ("198.18.0.3", 22),
        ]
        .into_iter()
        .enumerate()
        .map(|(id, (ip, port))| Row::observation(id as u64, ip.parse().unwrap(), port, true, true))
        .collect(),
    );
    table
}

#[test]
fn copying_selection_deduplicates_ips_in_numeric_view_order() {
    let mut t = table();
    t.select_visible();
    t.sort(0, false);
    assert_eq!(t.selected_ips(), "198.18.0.2\n198.18.0.3\n198.18.0.10");
    t.sort(0, true);
    assert_eq!(t.selected_ips(), "198.18.0.10\n198.18.0.3\n198.18.0.2");
    assert_eq!(t.selected.len(), 4);
}

#[test]
fn copying_filtered_selection_never_falls_back_to_hidden_or_focused_rows() {
    let mut t = table();
    t.select(1, false);
    t.select(0, true);
    t.filter("443");
    assert_eq!(t.selected_ips(), "198.18.0.2");
    t.filter("no-such-host");
    assert_eq!(t.selected_ips(), "");
    t.filter("");
    t.clear_selection();
    assert_eq!(t.selected_ips(), "");
    assert_eq!(t.focused, Some(0));
}

#[test]
fn escape_clears_range_anchor_but_keeps_keyboard_focus() {
    let mut t = table();
    t.select(0, false);
    t.select_with_modifiers(2, false, true);
    t.clear_selection();
    assert!(t.selected.is_empty());
    assert_eq!(t.focused, Some(2));
    assert_eq!(t.navigate(1, true), Some(3));
    assert_eq!(t.selected, [2, 3].into_iter().collect());
}
