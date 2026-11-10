//! AppKit text fields route Command editing shortcuts through the native menu.
//! Slint's default app menu omits Edit. Supply it while an export dialog is open;
//! its nil-target actions follow AppKit's responder chain, not Studio callbacks.
use objc2::{MainThreadMarker, rc::Retained, sel};
use objc2_app_kit::{NSApplication, NSEventModifierFlags, NSMenu, NSMenuItem};
use objc2_foundation::NSString;
use std::cell::RefCell;

struct DialogMenu {
    bar: Retained<NSMenu>,
    item: Retained<NSMenuItem>,
}

impl Drop for DialogMenu {
    fn drop(&mut self) {
        self.bar.removeItem(&self.item);
    }
}

thread_local! {
    // AppKit objects must remain on the UI thread; the export worker owns none.
    static MENU: RefCell<Option<DialogMenu>> = const { RefCell::new(None) };
}

pub(super) fn install() -> Result<(), &'static str> {
    let mtm = MainThreadMarker::new().ok_or("native dialog requires the UI thread")?;
    let bar = NSApplication::sharedApplication(mtm)
        .mainMenu()
        .ok_or("native application menu is unavailable")?;
    let title = NSString::from_str("Edit");
    // Do not duplicate or take ownership of a menu supplied by the backend.
    if bar.itemWithTitle(&title).is_some() {
        return Ok(());
    }
    let menu = NSMenu::initWithTitle(mtm.alloc(), &title);
    let command = NSEventModifierFlags::Command;
    for (label, action, key, modifiers) in [
        ("Undo", sel!(undo:), "z", command),
        (
            "Redo",
            sel!(redo:),
            "z",
            command | NSEventModifierFlags::Shift,
        ),
        ("Cut", sel!(cut:), "x", command),
        ("Copy", sel!(copy:), "c", command),
        ("Paste", sel!(paste:), "v", command),
        ("Select All", sel!(selectAll:), "a", command),
    ] {
        if label == "Cut" {
            menu.addItem(&NSMenuItem::separatorItem(mtm));
        }
        // SAFETY: standard AppKit action selectors have one sender argument.
        // The nil target (the default) lets AppKit validate the current responder.
        let item = unsafe {
            NSMenuItem::initWithTitle_action_keyEquivalent(
                mtm.alloc(),
                &NSString::from_str(label),
                Some(action),
                &NSString::from_str(key),
            )
        };
        item.setKeyEquivalentModifierMask(modifiers);
        menu.addItem(&item);
    }
    let item = NSMenuItem::new(mtm);
    item.setTitle(&title);
    item.setSubmenu(Some(&menu));
    bar.addItem(&item);
    MENU.with(|slot| *slot.borrow_mut() = Some(DialogMenu { bar, item }));
    Ok(())
}

pub(super) fn remove() {
    MENU.with(|slot| slot.borrow_mut().take());
}
