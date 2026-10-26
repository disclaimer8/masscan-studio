# Studio table ergonomics implementation plan

> **For agentic workers:** Use superpowers:executing-plans, including a final fresh review.

**Goal:** Make table keyboard operations and empty states match the visible results.

**Architecture:** Keep stable IDs and selection in studio-table. Slint owns focus,
viewport paging and clipboard delivery; Rust callbacks supply selected addresses.
Extract table callback wiring into a small module so tests exercise the same
bindings as the application, using Slint's exact-version headless testing backend.

**Tech stack:** Rust, Slint 1.18.1. No new production dependency.

**Spec:** 2026-10-23-cross-platform-qt-rust-design.md, table parity/keyboard scope.

## Global constraints

- Own only Studio table/UI code and its tests/docs. Do not edit engine, runner,
  network configuration or another worktree. Claude's live feth test is running.
- Do not launch a native window or use the real clipboard during that live test.
- System theme remains the default. No scanning or automatic actions are added.
- Preserve single-row context actions and filtered export behavior.

## Task 1: keyboard selection, copy and empty states

Files: studio-table/src/lib.rs and tests/selection.rs; studio-ui/src/main.rs,
new table_controls.rs; studio-ui/ui/main.slint; UI dev-dependencies/lock; README
and VERIFICATION.

Interfaces: Table::selected_ips() returns unique visible selected IPv4 strings
in current view order, joined by newlines. Hidden rows are excluded; there is no
fallback to focused/unselected rows. clear_selection() clears selection and
range anchor while retaining keyboard focus. Slint copy-selection callback
returns text; empty text leaves the clipboard unchanged.

- [ ] Add failing model tests for multi-select, duplicate IPs/different ports,
  filter/sort, no selection, Escape followed by Shift navigation.
- [ ] Extract the existing table callback wiring and add failing headless UI
  tests for actual Ctrl/Cmd+C, Escape and viewport-dependent PageUp/PageDown.
- [ ] Implement copy and clear; replace fixed ten-row paging with one visible
  page (at least one row). Show hidden selected count explicitly.
- [ ] Distinguish first-use, active waiting, completed empty history and an
  unmatched filter. Offer New scan when idle; Clear filter only for a filter.
- [ ] Run focused tests then cargo xtask test; review; exact-head green CI before
  merging. Headless tests do not establish native IME/clipboard/a11y acceptance.

## Review focus

- Hidden selection must not leak addresses to clipboard after filtering.
- Copy must preserve view order and not mutate selection or launch host actions.
- Clearing selection must not cause stale range selection on the next Shift move.
- Keyboard shortcuts in text fields/popups must retain their own semantics.
- Empty-state actions must not start a scan or become available during one.
