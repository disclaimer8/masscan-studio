//! Единственный путь тестов к временным файлам: свой каталог на каждый тест, который `Drop` удаляет целиком
//! (в том числе при панике теста). Имя каталога несёт pid и счётчик, поэтому параллельные тесты, повторные
//! запуски и соседние тестовые crate не сталкиваются. Модуль включается и в `src/lib.rs` (`#[path]`), и в
//! интеграционные тесты, поэтому каждый включающий crate берёт свою часть помощников.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NONCE: AtomicU64 = AtomicU64::new(0);

/// Каталог одного теста в `$TMPDIR`; удаляется вместе с содержимым при `Drop`.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new() -> Scratch {
        let n = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rmasscan-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Scratch(dir)
    }

    /// Сам каталог.
    pub fn dir(&self) -> &Path {
        &self.0
    }

    /// Путь `name` внутри каталога (файл не создаётся).
    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Создаёт `name` с содержимым `bytes` и возвращает путь.
    pub fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, bytes).expect("scratch file");
        p
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Scratch::new()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
