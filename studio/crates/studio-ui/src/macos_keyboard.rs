//! Adapt native macOS modifiers and Command characters to Slint's key stream.
use slint::platform::{Key, WindowEvent};
use slint::winit_030::{
    EventResult, WinitWindowAccessor,
    winit::{
        event::{ElementState, WindowEvent as NativeEvent},
        keyboard::{Key as NativeKey, ModifiersState, NamedKey},
        platform::modifier_supplement::KeyEventExtModifierSupplement,
    },
};

pub(super) fn connect(window: &slint::Window) {
    let mut keyboard = Keyboard::default();
    window.on_winit_window_event(move |window, event| keyboard.handle(window, event));
}

#[derive(Default)]
struct Keyboard {
    modifiers: ModifiersState,
}

impl Keyboard {
    fn modifiers_changed(&mut self, window: &slint::Window, modifiers: ModifiersState) {
        // Slint 1.18.1 tracks named modifier key presses, but macOS can report
        // only aggregate flags (e.g. accessibility input). Follow those flags,
        // including when both left and right modifier keys are held.
        // Match Slint's macOS convention: Command -> Control, Control -> Meta.
        for (flag, key) in [
            (ModifiersState::SHIFT, Key::Shift),
            (ModifiersState::CONTROL, Key::Meta),
            (ModifiersState::ALT, Key::Alt),
            (ModifiersState::SUPER, Key::Control),
        ] {
            if self.modifiers.contains(flag) != modifiers.contains(flag) {
                window.dispatch_event(if modifiers.contains(flag) {
                    WindowEvent::KeyPressed { text: key.into() }
                } else {
                    WindowEvent::KeyReleased { text: key.into() }
                });
            }
        }
        self.modifiers = modifiers;
    }

    fn command_text<'a>(&self, logical: &str, native: Option<&'a str>) -> Option<&'a str> {
        // AppKit's Command character can differ from the layout's ordinary
        // character (Russian Cmd+A: logical "ф", native "a"). Use AppKit's
        // character, not a hard-coded physical/QWERTY mapping. Leave Option,
        // Control, IME, dead keys and ordinary Unicode input to the backend.
        if !self.modifiers.super_key() || self.modifiers.alt_key() || self.modifiers.control_key() {
            return None;
        }
        native.filter(|text| {
            *text != logical && text.len() == 1 && text.as_bytes()[0].is_ascii_alphabetic()
        })
    }

    fn handle(&mut self, window: &slint::Window, event: &NativeEvent) -> EventResult {
        match event {
            NativeEvent::ModifiersChanged(modifiers) => {
                self.modifiers_changed(window, modifiers.state());
            }
            NativeEvent::Focused(false) => {
                self.modifiers_changed(window, ModifiersState::empty());
            }
            NativeEvent::KeyboardInput {
                event,
                is_synthetic: false,
                ..
            } => {
                if matches!(
                    event.logical_key,
                    NativeKey::Named(
                        NamedKey::Shift | NamedKey::Control | NamedKey::Alt | NamedKey::Super
                    )
                ) {
                    // Aggregate ModifiersChanged is authoritative; forwarding
                    // individual sides can release a modifier still held on
                    // the other side, or deliver each transition twice.
                    return EventResult::PreventDefault;
                }
                if let NativeKey::Character(logical) = &event.logical_key
                    && let Some(text) = self.command_text(logical, event.text_with_all_modifiers())
                {
                    let text = text.into();
                    window.dispatch_event(match event.state {
                        ElementState::Released => WindowEvent::KeyReleased { text },
                        ElementState::Pressed if event.repeat => {
                            WindowEvent::KeyPressRepeated { text }
                        }
                        ElementState::Pressed => WindowEvent::KeyPressed { text },
                    });
                    return EventResult::PreventDefault;
                }
            }
            _ => {}
        }
        EventResult::Propagate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slint::{ComponentHandle, platform::Key};

    slint::slint! {
        export component InputProbe inherits Window {
            in-out property <string> value <=> input.text;
            input := TextInput { single-line: true; }
            public function focus-input() { input.focus(); }
        }
    }

    fn setup() -> InputProbe {
        i_slint_backend_testing::init_no_event_loop();
        let ui = InputProbe::new().unwrap();
        ui.set_value("123456".into());
        ui.show().unwrap();
        ui.invoke_focus_input();
        ui
    }

    fn key(ui: &InputProbe, text: impl Into<slint::SharedString>) {
        let text = text.into();
        ui.window()
            .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
        ui.window()
            .dispatch_event(WindowEvent::KeyReleased { text });
    }

    #[test]
    fn command_flag_without_named_modifier_selects_all_in_real_text_input() {
        let ui = setup();
        let mut keyboard = Keyboard::default();
        keyboard.modifiers_changed(ui.window(), ModifiersState::SUPER);
        key(&ui, "a");
        keyboard.modifiers_changed(ui.window(), ModifiersState::empty());
        key(&ui, "8");
        assert_eq!(ui.get_value(), "8");
    }

    #[test]
    fn command_uses_native_shortcut_character_without_changing_plain_input() {
        let mut keyboard = Keyboard::default();
        assert_eq!(keyboard.command_text("ф", Some("a")), None);
        keyboard.modifiers = ModifiersState::SUPER;
        assert_eq!(keyboard.command_text("ф", Some("a")), Some("a"));
        assert_eq!(keyboard.command_text("a", Some("a")), None);
        keyboard.modifiers |= ModifiersState::SHIFT;
        assert_eq!(keyboard.command_text("Ф", Some("A")), Some("A"));
        keyboard.modifiers |= ModifiersState::ALT;
        assert_eq!(keyboard.command_text("ф", Some("a")), None);
        keyboard.modifiers = ModifiersState::CONTROL;
        assert_eq!(keyboard.command_text("ф", Some("\u{1}")), None);
        keyboard.modifiers = ModifiersState::SUPER;
        for text in [None, Some(""), Some("\u{1}"), Some("ф"), Some("ab")] {
            assert_eq!(keyboard.command_text("x", text), None);
        }
    }

    #[test]
    fn shift_flags_select_text_and_releasing_flags_restores_plain_typing() {
        let ui = setup();
        let mut keyboard = Keyboard::default();
        for _ in 0..6 {
            key(&ui, Key::RightArrow);
        }
        keyboard.modifiers_changed(ui.window(), ModifiersState::SHIFT);
        key(&ui, Key::LeftArrow);
        key(&ui, Key::LeftArrow);
        keyboard.modifiers_changed(ui.window(), ModifiersState::empty());
        key(&ui, "8");
        key(&ui, "0");
        assert_eq!(ui.get_value(), "123480");
    }

    #[test]
    fn focus_loss_releases_modifiers_before_plain_input() {
        let ui = setup();
        let mut keyboard = Keyboard::default();
        keyboard.modifiers_changed(ui.window(), ModifiersState::SUPER | ModifiersState::SHIFT);
        keyboard.handle(ui.window(), &NativeEvent::Focused(false));
        key(&ui, "a");
        key(&ui, "b");
        assert_eq!(ui.get_value(), "ab123456");
        assert!(keyboard.modifiers.is_empty());
    }
}
