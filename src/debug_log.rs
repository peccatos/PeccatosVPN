//! Глобальный отладочный лог (`--debug`): всё пишется в `debug.log`
//! рядом с рабочим каталогом с таймстампами. Потокобезопасно.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

static ENABLED: AtomicBool = AtomicBool::new(false);
static FILE: OnceLock<Mutex<Option<fs::File>>> = OnceLock::new();
static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Включает лог в файл `debug.log` (рабочий каталог). Вызывать до потоков.
pub fn init() {
    let path = std::env::current_dir()
        .unwrap_or_default()
        .join("debug.log");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok();
    let _ = LOG_PATH.set(path);
    let _ = FILE.set(Mutex::new(file));
    ENABLED.store(true, Ordering::Relaxed);
    log("=== session start ===");
}

pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn path() -> Option<&'static PathBuf> {
    LOG_PATH.get()
}

/// Записывает строку в debug.log (если --debug). Без паник при ошибке записи.
pub fn log(message: &str) {
    if !is_enabled() {
        return;
    }
    let Some(lock) = FILE.get() else {
        return;
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[{timestamp:010}] {message}\n");
    if let Ok(mut guard) = lock.lock() {
        if let Some(file) = guard.as_mut() {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// Лог с выравниванием значения (для пар ключ=значение).
#[allow(dead_code)]
pub fn log_kv(key: &str, value: impl std::fmt::Display) {
    log(&format!("{key} = {value}"));
}

/// Запись ошибки: ERROR-префикс + контекст anyhow.
#[allow(dead_code)]
pub fn log_error(context: &str, error: &dyn std::fmt::Display) {
    log(&format!("ERROR [{context}] {error}"));
}

#[macro_export]
macro_rules! dlog {
    ($($arg:tt)*) => {
        $crate::debug_log::log(&format!($($arg)*))
    };
}
