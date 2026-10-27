use crate::vless::{self, ProfileState, VlessProfile};
use std::{
    fs,
    path::{Path, PathBuf},
};

const MAX_DEPTH: usize = 5;
const MAX_FILES: usize = 512;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_URLS: usize = 2048;

pub const PUBLIC_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/githubmirror/ru-sni/vless_ru.txt",
    "https://tiagorrg.github.io/vless-checker/keys.json",
];

#[derive(Clone, Debug)]
pub struct SourceRef {
    pub display: String,
    #[allow(dead_code)]
    pub line: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct DiscoveredProfile {
    pub profile: VlessProfile,
    pub source: SourceRef,
    pub duplicate_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct DiscoveryResult {
    pub profiles: Vec<DiscoveredProfile>,
    pub diagnostics: Vec<String>,
    pub files_seen: usize,
    pub files_read: usize,
    pub urls_found: usize,
}

pub fn scan_directory(root: &Path) -> DiscoveryResult {
    let mut result = DiscoveryResult::default();
    let mut files = Vec::new();
    collect_files(root, 0, &mut files, &mut result.diagnostics);
    files.sort();
    let mut total_bytes = 0_u64;
    for path in files.into_iter().take(MAX_FILES) {
        result.files_seen += 1;
        let Ok(metadata) = fs::metadata(&path) else {
            result
                .diagnostics
                .push(format!("Не удалось прочитать {}", safe_path(root, &path)));
            continue;
        };
        if metadata.len() > MAX_FILE_BYTES
            || total_bytes.saturating_add(metadata.len()) > MAX_TOTAL_BYTES
        {
            result.diagnostics.push(format!(
                "Пропущен слишком большой файл {}",
                safe_path(root, &path)
            ));
            continue;
        }
        total_bytes += metadata.len();
        let Ok(text) = fs::read_to_string(&path) else {
            result
                .diagnostics
                .push(format!("Нечитаемый файл {}", safe_path(root, &path)));
            continue;
        };
        result.files_read += 1;
        add_text(
            &mut result,
            &text,
            SourceRef {
                display: safe_path(root, &path),
                line: None,
            },
        );
        if result.urls_found >= MAX_URLS {
            break;
        }
    }
    result
}

pub fn scan_public_source(text: &str, source: &str) -> DiscoveryResult {
    let mut result = DiscoveryResult::default();
    let source_ref = SourceRef {
        display: source.to_string(),
        line: None,
    };
    // Источник вида keys.json (vless-checker): {"best": "...", "top10": [{"key": "..."}]}
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') {
        let keys = extract_vless_from_json(text);
        if keys.is_empty() {
            result
                .diagnostics
                .push(format!("JSON-источник без VLESS-ключей: {source}"));
        } else {
            add_text(
                &mut result,
                &keys.join("\n"),
                SourceRef {
                    display: source.to_string(),
                    line: None,
                },
            );
        }
    } else {
        add_text(&mut result, text, source_ref);
    }
    result
}

/// Извлекает все vless://-ссылки из JSON произвольной вложенности
/// (значения полей "best", "key" и любые другие строковые поля).
fn extract_vless_from_json(text: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    collect_vless_strings(&value, &mut keys);
    keys
}

fn collect_vless_strings(value: &serde_json::Value, output: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => {
            if text.contains("vless://") {
                output.push(text.clone());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_vless_strings(item, output);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_vless_strings(item, output);
            }
        }
        _ => {}
    }
}

fn collect_files(
    root: &Path,
    depth: usize,
    output: &mut Vec<PathBuf>,
    diagnostics: &mut Vec<String>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        diagnostics.push(format!("Не удалось открыть источник {}", root.display()));
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_files(&path, depth + 1, output, diagnostics);
        } else if file_type.is_file() && is_text_candidate(&path) {
            output.push(path);
        }
    }
}

fn is_text_candidate(path: &Path) -> bool {
    match path.extension().and_then(|v| v.to_str()) {
        Some(extension) => matches!(
            extension,
            "txt" | "vless" | "conf" | "json" | "yaml" | "yml" | "subscription"
        ),
        None => true,
    }
}

fn add_text(result: &mut DiscoveryResult, text: &str, source: SourceRef) {
    for (line_number, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(start) = rest.find("vless://") {
            let candidate = &rest[start..];
            let end = candidate
                .find(char::is_whitespace)
                .unwrap_or(candidate.len());
            let trimmed = candidate[..end].trim_matches(|ch: char| "\"'`()[]{}<>,.;".contains(ch));
            result.urls_found += 1;
            if let Ok(profile) = vless::parse_for_discovery(trimmed, Path::new(&source.display)) {
                if matches!(profile.state, ProfileState::Valid) {
                    let key = profile_key(&profile);
                    if let Some(existing) = result
                        .profiles
                        .iter_mut()
                        .find(|item| profile_key(&item.profile) == key)
                    {
                        existing.duplicate_count += 1;
                    } else {
                        result.profiles.push(DiscoveredProfile {
                            profile,
                            source: SourceRef {
                                line: Some(line_number + 1),
                                ..source.clone()
                            },
                            duplicate_count: 0,
                        });
                    }
                }
            }
            rest = &candidate[end..];
            if rest.is_empty() {
                break;
            }
        }
    }
}

fn profile_key(profile: &VlessProfile) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        profile.host.to_ascii_lowercase(),
        profile.port,
        profile.security,
        profile.transport,
        profile.sni.as_deref().unwrap_or("")
    )
}

fn safe_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_multiple_urls_and_deduplicates() {
        let text = "vless://bad\nvless://8c8a8681-5444-4e18-a427-54f19eea6a77@host.invalid:443?security=tls&type=xhttp&sni=host.invalid&path=%2F\nvless://8c8a8681-5444-4e18-a427-54f19eea6a77@host.invalid:443?security=tls&type=xhttp&sni=host.invalid&path=%2F";
        let result = scan_public_source(text, "fixture");
        assert_eq!(result.profiles.len(), 1);
        assert_eq!(result.profiles[0].duplicate_count, 1);
        assert_eq!(result.urls_found, 3);
    }

    #[test]
    fn extracts_keys_from_json_source() {
        // формат keys.json (vless-checker): {"best": "...", "top10": [{"key": "..."}]}
        let json = r#"{
            "updated_at": "2026-10-27 05:27 UTC",
            "finland": {
                "best": "vless://8c8a8681-5444-4e18-a427-54f19eea6a77@host.invalid:443?security=tls&type=xhttp&sni=host.invalid&path=%2F",
                "top10": [
                    {"key": "vless://8c8a8681-5444-4e18-a427-54f19eea6a77@host.invalid:443?security=tls&type=xhttp&sni=host.invalid&path=%2F", "latency_ms": 8.5},
                    {"key": "vless://99999999-9999-4999-8999-999999999999@other.invalid:443?security=tls&type=xhttp&sni=other.invalid&path=%2F", "latency_ms": 9.1}
                ],
                "total_working": 2
            }
        }"#;
        let result = scan_public_source(json, "keys.json");
        assert_eq!(result.profiles.len(), 2);
        assert!(result.diagnostics.is_empty());
    }

    #[test]
    fn json_source_without_keys_reports_diagnostic() {
        let result = scan_public_source(r#"{"updated_at": "now"}"#, "keys.json");
        assert!(result.profiles.is_empty());
        assert!(!result.diagnostics.is_empty());
    }
}
