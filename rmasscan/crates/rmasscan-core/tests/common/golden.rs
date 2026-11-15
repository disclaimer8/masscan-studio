//! Проверка сумм манифеста golden-фикстур (AGPL-3.0, masscan © Robert David Graham): каждый
//! `input_sha256`/`output_sha256` обязан совпадать с sha256 файла рядом с манифестом. Без `serde_json`:
//! пары имя/сумма берутся из текста манифеста построчно. Подключается через `#[path]` вместе с
//! `sha256.rs` (`super::sha256`), поэтому без внешних крейтов.
#![allow(dead_code)]

use std::fs;
use std::path::Path;

use super::sha256::Sha256;

/// Значение строкового поля `"key": "value"` в строке манифеста.
fn string_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix('"')?.strip_prefix(key)?;
    let rest = rest.strip_prefix("\": \"")?;
    rest.split('"').next()
}

/// Сверяет суммы файлов с манифестом: число проверенных файлов или ошибка с именем файла и обеими
/// суммами. Сумма относится к полю `input`/`output` своего кейса: имена сбрасываются на строке `"name"`
/// (начало кейса), вложенные `frames.*.output` (глубже отступом, чем `name`) их не перезаписывают, а имя
/// расходуется суммой, так что сумма без своего имени это ошибка, а не чужой файл.
pub fn check_manifest_hashes(dir: &Path, manifest_text: &str) -> Result<usize, String> {
    let (mut input, mut output) = (None, None);
    let mut case_indent = None;
    let mut checked = 0usize;
    for line in manifest_text.lines() {
        let indent = line.len() - line.trim_start().len();
        if string_field(line, "name").is_some() {
            case_indent = Some(indent);
            (input, output) = (None, None);
            continue;
        }
        if case_indent.is_some_and(|c| indent > c) {
            // Вложенные объекты кейса (`frames`): свои `output` без сумм.
            continue;
        }
        let (file, want) = if let Some(v) = string_field(line, "input") {
            input = Some(v);
            continue;
        } else if let Some(v) = string_field(line, "output") {
            output = Some(v);
            continue;
        } else if let Some(v) = string_field(line, "input_sha256") {
            (input.take(), v)
        } else if let Some(v) = string_field(line, "output_sha256") {
            (output.take(), v)
        } else {
            continue;
        };
        let file = file.ok_or_else(|| format!("sum {want} without a preceding file name"))?;
        let bytes = fs::read(dir.join(file)).map_err(|e| format!("{file}: {e}"))?;
        let mut h = Sha256::new();
        h.update(&bytes);
        let got = h.finish();
        if got != want {
            return Err(format!("{file}: manifest sha256 {want}, file sha256 {got}"));
        }
        checked += 1;
    }
    Ok(checked)
}
