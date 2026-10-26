//! Result-table callbacks shared by the application and headless UI tests.
use super::*;

pub(super) fn connect(ui: &MainWindow, rows: Rc<Rows>) {
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_filter(move |s| {
        m.table.borrow_mut().filter(&s);
        m.changed();
        if let Some(ui) = w.upgrade() {
            ui.set_filter_query(s);
            m.summary(&ui);
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_order(move |c, d| {
        m.table.borrow_mut().sort(c as usize, d);
        m.changed();
        if let Some(ui) = w.upgrade() {
            m.summary(&ui);
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_choose(move |i, e, r| {
        m.table.borrow_mut().select_with_modifiers(i as usize, e, r);
        m.changed();
        if let Some(ui) = w.upgrade() {
            m.summary(&ui);
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_navigate(move |d, r| {
        let n = m.table.borrow_mut().navigate(d, r);
        m.changed();
        if let Some(ui) = w.upgrade() {
            m.summary(&ui);
        }
        n.map(|n| n as i32).unwrap_or(-1)
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_select_visible(move || {
        m.table.borrow_mut().select_visible();
        m.changed();
        if let Some(ui) = w.upgrade() {
            m.summary(&ui);
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_clear_selection(move || {
        m.table.borrow_mut().clear_selection();
        m.changed();
        if let Some(ui) = w.upgrade() {
            m.summary(&ui);
        }
    });
    let w = ui.as_weak();
    let m = rows.clone();
    ui.on_copy_selection(move || {
        let text = m.table.borrow().selected_ips();
        if !text.is_empty()
            && let Some(ui) = w.upgrade()
        {
            let count = text.lines().count();
            ui.set_action_notice(
                format!(
                    "Copied {count} IP {}",
                    if count == 1 { "address" } else { "addresses" }
                )
                .into(),
            );
        }
        text.into()
    });
    let w = ui.as_weak();
    ui.on_activate(move |i| {
        if let (Some(ui), Some(row)) = (w.upgrade(), rows.row_data(i as usize)) {
            ui.set_inspector_details(row);
            ui.set_inspector_open(true);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::platform::{Key, WindowEvent};

    slint::slint! {
        export component ClipboardProbe inherits Window {
            input := TextInput { single-line: false; }
            public function read-clipboard() -> string {
                input.text = ""; input.paste(); return input.text;
            }
        }
    }
    fn setup() -> (MainWindow, Rc<Rows>) {
        i_slint_backend_testing::init_no_event_loop();
        let ui = MainWindow::new().unwrap();
        ui.window().set_size(slint::LogicalSize::new(1160., 740.));
        let rows = Rc::new(Rows {
            observations: RefCell::new(HashMap::new()),
            hosts: RefCell::new(HashMap::new()),
            table: RefCell::new(Table::new(0)),
            keys: RefCell::new(HashMap::new()),
            notify: ModelNotify::default(),
            summary_dirty: Cell::new(true),
            simulation: Cell::new(true),
            archived: Cell::new(false),
        });
        rows.add(
            (2..62)
                .map(|n| studio_store::SavedRow {
                    row: studio_protocol::Row {
                        ip: format!("198.18.0.{n}"),
                        port: 80,
                        open: true,
                    },
                    discovered_at: None,
                })
                .collect(),
        );
        ui.set_rows(ModelRc::from(rows.clone()));
        connect(&ui, rows.clone());
        rows.summary(&ui);
        ui.show().unwrap();
        ui.invoke_focus_results();
        ui.invoke_choose(0, false, false);
        assert_eq!(ui.get_active_row(), 0);
        (ui, rows)
    }
    fn key(ui: &MainWindow, text: impl Into<slint::SharedString>) {
        let text = text.into();
        ui.window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        ui.window()
            .dispatch_event(WindowEvent::KeyReleased { text });
    }
    fn chord(ui: &MainWindow, modifier: Key, text: impl Into<slint::SharedString>) {
        ui.window().dispatch_event(WindowEvent::KeyPressed {
            text: modifier.into(),
        });
        key(ui, text);
        ui.window().dispatch_event(WindowEvent::KeyReleased {
            text: modifier.into(),
        });
    }

    #[test]
    fn copy_keys_use_visible_selection_and_escape_preserves_clipboard() {
        let (ui, rows) = setup();
        let probe = ClipboardProbe::new().unwrap();
        ui.invoke_choose(2, true, false);
        for modifier in [Key::Control, Key::Meta] {
            chord(&ui, modifier, "c");
            assert_eq!(probe.invoke_read_clipboard(), "198.18.0.2\n198.18.0.4");
        }
        key(&ui, Key::Escape);
        assert!(rows.table.borrow().selected.is_empty());
        chord(&ui, Key::Control, "c");
        assert_eq!(probe.invoke_read_clipboard(), "198.18.0.2\n198.18.0.4");
        key(&ui, Key::DownArrow);
        assert_eq!(ui.get_active_row(), 3);
        assert_eq!(ui.get_selection_count(), 1);
    }

    #[test]
    fn page_keys_follow_viewport_size_and_home_end_keep_navigation() {
        let (ui, _) = setup();
        key(&ui, Key::PageDown);
        let short = ui.get_active_row();
        key(&ui, Key::Home);
        assert_eq!(ui.get_active_row(), 0);
        ui.window().set_size(slint::LogicalSize::new(1160., 1040.));
        key(&ui, Key::PageDown);
        assert!(
            ui.get_active_row() > short,
            "page size stayed fixed: {short}"
        );
        key(&ui, Key::PageUp);
        assert_eq!(ui.get_active_row(), 0);
        key(&ui, Key::End);
        assert_eq!(ui.get_active_row(), 59);
        key(&ui, Key::Home);
        chord(&ui, Key::Shift, Key::PageDown);
        assert_eq!(ui.get_selection_count(), ui.get_active_row() + 1);
    }

    #[test]
    fn escape_in_context_menu_does_not_clear_table_selection() {
        let (ui, rows) = setup();
        ui.invoke_choose(2, true, false);
        chord(&ui, Key::Shift, Key::F10);
        key(&ui, Key::Escape);
        assert_eq!(rows.table.borrow().selected.len(), 2);
    }

    #[test]
    fn page_boundaries_use_content_viewport_and_keep_focused_row_fully_visible() {
        let (ui, _) = setup();
        for width in [820., 1160.] {
            for height in 740..775 {
                ui.window()
                    .set_size(slint::LogicalSize::new(width, height as f32));
                key(&ui, Key::Home);
                let viewport = ui.get_results_viewport_height();
                let expected = (viewport / 30.).floor().max(1.) as i32;
                key(&ui, Key::PageDown);
                assert_eq!(
                    ui.get_active_row(),
                    expected,
                    "width={width}, height={height}, viewport={viewport}"
                );
                let bottom = (ui.get_active_row() + 1) as f32 * 30. + ui.get_results_scroll_y();
                assert!(
                    bottom <= viewport + 0.1,
                    "focused row clipped: bottom={bottom}, viewport={viewport}"
                );
            }
        }
    }

    #[test]
    fn idle_summary_never_borrows_or_walks_the_unchanged_table() {
        let (ui, rows) = setup();
        let _table = rows.table.borrow_mut();
        // A clean summary has no reason to read the model, at any row count.
        for _ in 0..20 {
            rows.summary(&ui);
        }
    }

    #[test]
    fn summary_refreshes_after_sort_enrichment_batches_and_history_replacement() {
        let (ui, rows) = setup();
        ui.invoke_order(0, true);
        assert_eq!(ui.get_active_row(), 59);
        ui.invoke_filter("printer.local".into());
        assert_eq!(ui.get_active_row(), -1);
        assert_eq!(ui.get_selection_label(), "1 selected · 1 hidden");

        let mut host = studio_inspection::HostInfo::new("198.18.0.2".into());
        host.hostname = Some("printer.local".into());
        rows.enrich(vec![host]);
        rows.summary(&ui);
        assert_eq!(ui.get_summary(), "1 of 60 saved results");
        assert_eq!(ui.get_active_row(), 0);
        assert_eq!(ui.get_details().hostname, "printer.local");
        assert_eq!(ui.get_selection_label(), "1 selected");

        let saved = |ip: &str| studio_store::SavedRow {
            row: studio_protocol::Row {
                ip: ip.into(),
                port: 80,
                open: true,
            },
            discovered_at: None,
        };
        rows.add(vec![saved("198.18.0.63")]);
        rows.add(vec![saved("198.18.0.64")]);
        rows.summary(&ui);
        assert_eq!(ui.get_summary(), "1 of 62 saved results");
        {
            let _table = rows.table.borrow_mut();
            rows.summary(&ui);
        }

        clear_view(&rows, &ui);
        rows.summary(&ui);
        assert_eq!(ui.get_summary(), "0 of 0 saved results");
        assert_eq!(ui.get_selection_count(), 0);
        assert_eq!(ui.get_active_row(), -1);
        assert_eq!(ui.get_details().ip, "");
        rows.add(vec![saved("198.18.0.9")]);
        rows.summary(&ui);
        assert_eq!(ui.get_summary(), "1 of 1 saved results");
        ui.invoke_choose(0, false, false);
        assert_eq!(ui.get_details().ip, "198.18.0.9");
        ui.invoke_select_visible();
        assert_eq!(ui.get_selection_count(), 1);
        ui.invoke_clear_selection();
        assert_eq!(ui.get_selection_count(), 0);
    }

    #[test]
    fn filter_hides_selected_addresses_and_text_input_keeps_its_shortcuts() {
        let (ui, rows) = setup();
        let probe = ClipboardProbe::new().unwrap();
        ui.invoke_choose(2, true, false);
        ui.invoke_filter("198.18.0.2 ".into());
        assert_eq!(ui.get_active_row(), -1);
        assert_eq!(ui.get_selection_label(), "2 selected · 1 hidden");
        chord(&ui, Key::Control, "c");
        assert_eq!(probe.invoke_read_clipboard(), "198.18.0.2");
        // Slint text inputs receive the normalized Control modifier. Native
        // Command mapping belongs to the OS backend, outside this headless test.
        let modifier = Key::Control;
        chord(&ui, modifier, "f");
        chord(&ui, modifier, "a");
        chord(&ui, modifier, "c");
        assert_eq!(probe.invoke_read_clipboard(), "198.18.0.2 ");
        key(&ui, Key::Escape);
        assert_eq!(rows.table.borrow().selected.len(), 2);
    }

    #[test]
    fn empty_states_distinguish_first_use_waiting_history_and_filter() {
        let (ui, rows) = setup();
        *rows.table.borrow_mut() = Table::new(0);
        rows.changed();
        rows.summary(&ui);
        assert_eq!(ui.get_empty_title(), "Start your first scan");
        assert_eq!(ui.get_empty_action(), "New scan");
        ui.set_process_active(true);
        assert_eq!(ui.get_empty_title(), "Waiting for results");
        assert_eq!(ui.get_empty_action(), "");
        ui.set_process_active(false);
        ui.set_history_index(0);
        assert_eq!(ui.get_empty_title(), "No results saved");
        assert_eq!(ui.get_empty_action(), "New scan");
        ui.invoke_filter("missing".into());
        assert_eq!(ui.get_empty_title(), "No matching results");
        assert_eq!(ui.get_empty_action(), "Clear filter");
    }
}
