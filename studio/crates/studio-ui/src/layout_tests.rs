use super::*;
use i_slint_backend_testing::ElementHandle;

#[test]
fn header_controls_fit_minimum_width_in_idle_and_authorizing_states() {
    i_slint_backend_testing::init_no_event_loop();
    let ui = MainWindow::new().unwrap();
    ui.set_scan_backend_label("Simulation · no packets".into());
    ui.set_authorization_available(true);
    ui.show().unwrap();
    for width in [820., 950., 1099., 1100., 1160.] {
        ui.window().set_size(slint::LogicalSize::new(width, 540.));
        for authorizing in [false, true] {
            ui.set_authorizing(authorizing);
            let mut previous_right = 0.;
            for label in [
                "History…",
                "New scan",
                "Scanner setup",
                if authorizing {
                    "Cancel authorization"
                } else {
                    "Authorize"
                },
                "Theme: System",
            ] {
                let item = ElementHandle::find_by_accessible_label(&ui, label)
                    .next()
                    .expect(label);
                let pos = item.absolute_position();
                let size = item.size();
                assert!(
                    pos.x >= previous_right && pos.x + size.width <= width,
                    "{label} overlaps or clips at width={width}, authorizing={authorizing}: x={}, width={}, previous_right={previous_right}",
                    pos.x,
                    size.width
                );
                assert!(
                    pos.y >= 0. && pos.y + size.height <= 110.,
                    "{label} left the header"
                );
                previous_right = pos.x + size.width;
            }
            let mode = ElementHandle::find_by_accessible_label(&ui, "Simulation · no packets")
                .next()
                .unwrap();
            let history = ElementHandle::find_by_accessible_label(&ui, "History…")
                .next()
                .unwrap();
            let status = ElementHandle::find_by_accessible_label(&ui, "Ready")
                .next()
                .unwrap();
            let mode_right = mode.absolute_position().x + mode.size().width;
            assert!(status.absolute_position().x >= mode_right);
            assert!(status.absolute_position().x + status.size().width <= width);
            if width >= 1100. {
                assert!(history.absolute_position().x >= mode_right);
                assert!(status.absolute_position().x >= previous_right);
            } else {
                assert!(
                    history.absolute_position().y
                        >= mode.absolute_position().y + mode.size().height
                );
            }
        }
    }
}
