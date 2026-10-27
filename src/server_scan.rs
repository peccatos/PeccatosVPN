use anyhow::{Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CANDIDATES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct EndpointCandidate {
    pub host: String,
    pub port: u16,
    pub scheme: Option<String>,
    pub source: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeStatus {
    Reachable,
    Unreachable(String),
    NotChecked,
}

impl EndpointCandidate {
    pub fn label(&self) -> String {
        match &self.scheme {
            Some(scheme) => format!("{scheme}://{}:{}", self.host, self.port),
            None => format!("{}:{}", self.host, self.port),
        }
    }

    pub fn probe(&self, timeout: Duration) -> ProbeStatus {
        let address = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let result = (|| {
            let mut addresses = address
                .to_socket_addrs()
                .with_context(|| format!("не удалось разрешить {}", self.host))?;
            let socket = addresses.next().context("DNS не вернул адрес")?;
            std::net::TcpStream::connect_timeout(&socket, timeout)
                .with_context(|| format!("TCP-подключение к {} не удалось", self.label()))?;
            Ok::<(), anyhow::Error>(())
        })();

        match result {
            Ok(()) => ProbeStatus::Reachable,
            Err(error) => ProbeStatus::Unreachable(error.to_string()),
        }
    }
}

pub fn scan_bundled_app(root: &Path) -> Result<Vec<EndpointCandidate>> {
    let app_dir = root.join("app");
    if !app_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut total = 0_u64;
    let mut candidates = BTreeSet::new();
    for entry in fs::read_dir(&app_dir)
        .with_context(|| format!("Не удалось открыть {}", app_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || !is_allowed_file(&path) {
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.len() > MAX_FILE_BYTES || total.saturating_add(metadata.len()) > MAX_TOTAL_BYTES
        {
            continue;
        }
        total += metadata.len();
        let bytes = fs::read(&path)?;
        for candidate in parse_candidates(&bytes, &path) {
            candidates.insert(candidate);
            if candidates.len() >= MAX_CANDIDATES {
                return Ok(candidates.into_iter().collect());
            }
        }
    }

    Ok(candidates.into_iter().collect())
}

fn is_allowed_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("jar") | Some("cfg") | Some("json") | Some("properties") | Some("xml")
    )
}

pub fn parse_candidates(bytes: &[u8], source: &Path) -> Vec<EndpointCandidate> {
    let text = String::from_utf8_lossy(bytes);
    let mut result = BTreeMap::new();
    let mut token = String::new();

    for character in text.chars() {
        if character.is_ascii_alphanumeric()
            || matches!(
                character,
                '.' | ':' | '/' | '[' | ']' | '-' | '_' | '?' | '@'
            )
        {
            token.push(character);
        } else {
            add_token_candidates(&token, source, &mut result);
            token.clear();
        }
    }
    add_token_candidates(&token, source, &mut result);
    result.into_values().collect()
}

fn add_token_candidates(
    token: &str,
    source: &Path,
    result: &mut BTreeMap<(String, u16), EndpointCandidate>,
) {
    let token = token.trim_matches(|character| matches!(character, '/' | '?' | ':'));
    if token.is_empty() || token.len() > 512 {
        return;
    }

    let (scheme, address) = if let Some((scheme, address)) = token.split_once("://") {
        if !matches!(scheme, "http" | "https" | "socks5" | "socks5h") {
            return;
        }
        (Some(scheme.to_string()), address)
    } else {
        (None, token)
    };

    if address.contains('@') || address.contains('/') || address.contains('?') {
        return;
    }
    let Some((host, port)) = split_host_port(address) else {
        return;
    };
    if !valid_host(host) || looks_like_service_host(host) || port == 0 {
        return;
    }

    let host = host.to_ascii_lowercase();
    let key = (host.clone(), port);
    result.entry(key).or_insert(EndpointCandidate {
        host,
        port,
        scheme,
        source: source.to_path_buf(),
    });
}

fn split_host_port(address: &str) -> Option<(&str, u16)> {
    if let Some(stripped) = address.strip_prefix('[') {
        let (host, rest) = stripped.split_once(']')?;
        let port = rest.strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    let (host, port) = address.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }
    Some((host, port.parse().ok()?))
}

fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.chars().any(char::is_control) {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    })
}

fn looks_like_service_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    [
        "localhost",
        "example.com",
        "example.org",
        "example.net",
        "google.com",
        "cloudflare.com",
        "github.com",
        "apache.org",
        "openjdk.org",
        "mozilla.org",
    ]
    .iter()
    .any(|suffix| lower == *suffix || lower.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_deduplicates_endpoints() {
        let source = PathBuf::from("fixture.jar");
        let result = parse_candidates(
            b"https://vpn.example.invalid:443 and vpn.example.invalid:443",
            &source,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host, "vpn.example.invalid");
        assert_eq!(result[0].port, 443);
    }

    #[test]
    fn rejects_credentials_and_invalid_ports() {
        let source = PathBuf::from("fixture.jar");
        let result = parse_candidates(
            b"https://user:secret@vpn.example.invalid:443 vpn.example.invalid:0 vpn.example.invalid:65536",
            &source,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn extracts_bracketed_ipv6() {
        let source = PathBuf::from("fixture.jar");
        let result = parse_candidates(b"socks5://[2001:db8::1]:1080", &source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host, "2001:db8::1");
        assert_eq!(result[0].port, 1080);
    }
}
