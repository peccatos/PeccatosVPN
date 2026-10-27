use crate::vless::VlessProfile;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

const XHTTP_KEYS: &[&str] = &[
    "security",
    "type",
    "sni",
    "fp",
    "path",
    "host",
    "mode",
    "alpn",
    "extra",
    "allowInsecure",
    "insecure",
    "encryption",
];

pub fn stream_settings(profile: &VlessProfile) -> Result<Value> {
    match (profile.security.as_str(), profile.transport.as_str()) {
        ("tls", "xhttp") => map_tls_xhttp(profile),
        ("reality", "tcp") => map_reality_tcp(profile),
        ("reality", "grpc") => map_reality_grpc(profile),
        (security, transport) => {
            bail!("Комбинация security={security} и type={transport} не поддерживается")
        }
    }
}

fn map_reality_tcp(profile: &VlessProfile) -> Result<Value> {
    Ok(json!({
        "network": "tcp",
        "security": "reality",
        "realitySettings": reality_settings(profile)?,
    }))
}

fn map_reality_grpc(profile: &VlessProfile) -> Result<Value> {
    let query = profile.params();
    let service_name = required(query, "serviceName")?;
    let mut grpc = json!({ "serviceName": service_name });
    if let Some(authority) = non_empty(query, "authority") {
        grpc["authority"] = json!(authority);
    }
    Ok(json!({
        "network": "grpc",
        "security": "reality",
        "realitySettings": reality_settings(profile)?,
        "grpcSettings": grpc,
    }))
}

fn map_tls_xhttp(profile: &VlessProfile) -> Result<Value> {
    let query = profile.params();
    reject_unknown_xhttp_keys(query)?;
    reject_insecure_override(query)?;
    let sni = profile
        .sni
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("xHTTP требует sni")?;
    let path = required(query, "path")?;
    if !path.starts_with('/') || path.len() > 2048 || path.chars().any(char::is_control) {
        bail!("xHTTP path имеет недопустимый формат");
    }
    let mode = non_empty(query, "mode").unwrap_or("auto");
    if !matches!(mode, "auto" | "packet-up" | "stream-up" | "stream-one") {
        bail!("xHTTP mode не поддерживается");
    }
    let mut tls = json!({ "serverName": sni, "allowInsecure": false });
    if let Some(alpn) = non_empty(query, "alpn") {
        let values = alpn
            .split(',')
            .map(str::trim)
            .filter(|v| matches!(*v, "h3" | "h2" | "http/1.1"))
            .collect::<Vec<_>>();
        if values.is_empty() {
            bail!("xHTTP ALPN не поддерживается");
        }
        tls["alpn"] = json!(values);
    }
    let mut xhttp = json!({ "path": path, "mode": mode });
    if let Some(host) = non_empty(query, "host") {
        validate_header_value(host)?;
        xhttp["host"] = json!(host);
    }
    if let Some(extra) = non_empty(query, "extra") {
        // The exported extra object is client/version-specific. Do not copy it
        // into Xray until each field has a typed whitelist mapping.
        let _ = extra;
        bail!("xHTTP extra пока не поддерживается безопасным mapping-ом");
    }
    Ok(json!({
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": tls,
        "xhttpSettings": xhttp,
    }))
}

fn reality_settings(profile: &VlessProfile) -> Result<Value> {
    let query = profile.params();
    let sni = profile
        .sni
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("Reality требует sni")?;
    let fingerprint = required(query, "fp")?;
    let public_key = required(query, "pbk")?;
    let mut settings = json!({
        "serverName": sni,
        "fingerprint": fingerprint,
        "publicKey": public_key,
    });
    if let Some(short_id) = non_empty(query, "sid") {
        settings["shortId"] = json!(short_id);
    }
    if let Some(spider_x) = non_empty(query, "spx") {
        settings["spiderX"] = json!(spider_x);
    }
    Ok(settings)
}

fn required<'a>(
    query: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Result<&'a str> {
    non_empty(query, key).with_context(|| format!("профиль требует параметр {key}"))
}

fn non_empty<'a>(
    query: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    query
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn reject_unknown_xhttp_keys(query: &std::collections::HashMap<String, String>) -> Result<()> {
    if let Some(key) = query.keys().find(|key| !XHTTP_KEYS.contains(&key.as_str())) {
        bail!("xHTTP параметр не поддерживается: {key}");
    }
    Ok(())
}

fn reject_insecure_override(query: &std::collections::HashMap<String, String>) -> Result<()> {
    for key in ["allowInsecure", "insecure"] {
        if let Some(value) = non_empty(query, key) {
            if !matches!(value, "0" | "false") {
                bail!("TLS override {key} запрещён");
            }
        }
    }
    Ok(())
}

fn validate_header_value(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || value.chars().any(char::is_control)
        || value.contains(':')
    {
        bail!("xHTTP host имеет недопустимый формат");
    }
    Ok(())
}

pub fn build_config(profile: &VlessProfile, socks_port: u16) -> Result<Value> {
    let uuid = profile.uuid();
    if uuid.is_empty() {
        bail!("В профиле отсутствует UUID");
    }
    let flow = profile.flow.clone().unwrap_or_default();
    Ok(json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
            "sniffing": { "enabled": false }
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": { "vnext": [{
                "address": profile.host,
                "port": profile.port,
                "users": [{ "id": uuid, "encryption": "none", "flow": flow }]
            }]},
            "streamSettings": stream_settings(profile)?
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless;
    use std::path::Path;

    #[test]
    fn maps_tls_xhttp_without_extra() {
        let raw = "vless://8c8a8681-5444-4e18-a427-54f19eea6a77@host.invalid:2053?security=tls&type=xhttp&sni=host.invalid&path=%2Fapi&mode=auto&host=host.invalid&alpn=h2%2Chttp%2F1.1";
        let profile = vless::parse_for_test(raw, Path::new("x.txt")).unwrap();
        let config = build_config(&profile, 19001).unwrap();
        assert_eq!(config["outbounds"][0]["streamSettings"]["network"], "xhttp");
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"],
            "/api"
        );
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"],
            false
        );
    }
}
