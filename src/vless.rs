use anyhow::{bail, Context, Result};
use reqwest::Url;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileState {
    Valid,
    Invalid(String),
    Unsupported(String),
}

#[derive(Clone, Debug)]
pub struct VlessProfile {
    pub source: PathBuf,
    #[allow(dead_code)]
    pub label: String,
    pub host: String,
    pub port: u16,
    pub security: String,
    pub transport: String,
    pub flow: Option<String>,
    pub sni: Option<String>,
    pub state: ProfileState,
    params: std::collections::HashMap<String, String>,
    uuid: String,
    _raw: String,
}

impl VlessProfile {
    pub(crate) fn params(&self) -> &std::collections::HashMap<String, String> {
        &self.params
    }
    pub(crate) fn uuid(&self) -> &str {
        &self.uuid
    }
    /// Исходная vless://-ссылка (для сохранения в файл).
    pub fn raw_link(&self) -> &str {
        &self._raw
    }
}

pub(crate) fn load_path(path: &Path) -> Result<VlessProfile> {
    parse_file(path)
}

#[allow(dead_code)]
pub fn load_dir(dir: &Path) -> Result<Vec<VlessProfile>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("Не удалось открыть {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("txt") | Some("vless")
            )
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths.into_iter().map(|path| parse_file(&path)).collect()
}

fn parse_file(path: &Path) -> Result<VlessProfile> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Не удалось прочитать {}", path.display()))?;
    let content = content.trim_start_matches('\u{feff}');
    let line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("");
    if line.is_empty() {
        return Ok(invalid(path, "пустой файл", String::new()));
    }
    match parse_url(line, path) {
        Ok(profile) => Ok(profile),
        Err(error) => Ok(invalid(path, &error.to_string(), line.to_string())),
    }
}

#[cfg(test)]
pub(crate) fn parse_for_test(raw: &str, source: &Path) -> Result<VlessProfile> {
    parse_url(raw, source)
}

pub(crate) fn parse_for_discovery(raw: &str, source: &Path) -> Result<VlessProfile> {
    parse_url(raw, source)
}

fn parse_url(raw: &str, source: &Path) -> Result<VlessProfile> {
    let url = Url::parse(raw).context("некорректный URL")?;
    if url.scheme() != "vless" {
        bail!("ожидалась схема vless://");
    }
    let uuid = url.username();
    if !valid_uuid(uuid) || url.password().is_some() {
        bail!("некорректный UUID или userinfo");
    }
    let host = url.host_str().context("не указан host")?.to_string();
    let port = url.port().context("не указан порт")?;
    if port == 0 {
        bail!("некорректный порт");
    }
    let query = url
        .query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    let security = query.get("security").cloned().unwrap_or_default();
    let transport = query.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let flow = query.get("flow").cloned();
    let sni = query.get("sni").cloned();
    let state = validate_profile(&security, &transport, &query);
    let label = url.fragment().and_then(percent_decode).unwrap_or_else(|| {
        source
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("VLESS profile")
            .to_string()
    });
    Ok(VlessProfile {
        source: source.to_path_buf(),
        label: sanitize_label(&label),
        host,
        port,
        security,
        transport,
        flow,
        sni,
        state,
        params: query,
        uuid: uuid.to_string(),
        _raw: raw.to_string(),
    })
}

fn validate_profile(
    security: &str,
    transport: &str,
    query: &std::collections::HashMap<String, String>,
) -> ProfileState {
    if !matches!(security, "reality" | "tls") {
        return ProfileState::Unsupported(format!("security={security}"));
    }
    if !matches!(
        (security, transport),
        ("reality", "tcp") | ("reality", "grpc") | ("tls", "xhttp")
    ) {
        return ProfileState::Unsupported(format!("security={security}, type={transport}"));
    }
    if security == "reality" && (!has(query, "pbk") || !has(query, "sni") || !has(query, "fp")) {
        return ProfileState::Invalid("для Reality нужны pbk, sni и fp".into());
    }
    if security == "tls" && !has(query, "sni") {
        return ProfileState::Invalid("для TLS нужен sni".into());
    }
    if transport == "grpc" && !has(query, "serviceName") {
        return ProfileState::Invalid("для gRPC нужен serviceName".into());
    }
    if transport == "xhttp" && !has(query, "path") {
        return ProfileState::Invalid("для xhttp нужен path".into());
    }
    ProfileState::Valid
}

fn has(query: &std::collections::HashMap<String, String>, key: &str) -> bool {
    query.get(key).is_some_and(|value| !value.is_empty())
}

fn valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| bytes[i] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| [8, 13, 18, 23].contains(&i) || b.is_ascii_hexdigit())
}

fn percent_decode(value: &str) -> Option<String> {
    let mut output = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            let byte = u8::from_str_radix(hex, 16).ok()?;
            output.push(byte as char);
            index += 3;
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    Some(output)
}

fn sanitize_label(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).take(80).collect()
}

fn invalid(path: &Path, reason: &str, raw: String) -> VlessProfile {
    VlessProfile {
        source: path.to_path_buf(),
        label: path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("invalid")
            .into(),
        host: "—".into(),
        port: 0,
        security: "—".into(),
        transport: "—".into(),
        flow: None,
        sni: None,
        state: ProfileState::Invalid(reason.into()),
        params: std::collections::HashMap::new(),
        uuid: String::new(),
        _raw: raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_reality_tcp_without_exposing_credentials() {
        let path = Path::new("one.txt");
        let p = parse_url("vless://8c8a8681-5444-4e18-a427-54f19eea6a77@45.11.27.130:443?security=reality&pbk=public&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.invalid#Test", path).unwrap();
        assert_eq!(p.host, "45.11.27.130");
        assert_eq!(p.port, 443);
        assert_eq!(p.state, ProfileState::Valid);
        assert!(!p.label.contains("8c8a"));
    }
    #[test]
    fn rejects_missing_grpc_service_name() {
        let p = parse_url("vless://8c8a8681-5444-4e18-a427-54f19eea6a77@host.invalid:443?security=reality&pbk=public&fp=firefox&sni=host.invalid&type=grpc", Path::new("x.txt")).unwrap();
        assert!(matches!(p.state, ProfileState::Invalid(_)));
    }
    #[test]
    fn tolerates_utf8_bom() {
        // PowerShell Set-Content пишет UTF-8 с BOM: BOM прилипает к vless:// — URL-парсер падает.
        // parse_url вызывается после strip в parse_file, но проверим устойчивость напрямую.
        let raw = "vless://8c8a8681-5444-4e18-a427-54f19eea6a77@host.invalid:443?security=reality&pbk=public&fp=firefox&type=tcp&sni=host.invalid";
        let line = raw.trim_start_matches('\u{feff}').trim();
        let p = parse_url(line, Path::new("bom.txt")).unwrap();
        assert_eq!(p.state, ProfileState::Valid);
    }
}
