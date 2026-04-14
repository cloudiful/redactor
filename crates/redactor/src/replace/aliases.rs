use ipnet::IpNet;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

pub(crate) fn stable_domain_alias(value: &str) -> String {
    let labels = value.split('.').collect::<Vec<_>>();
    if labels.len() >= 3 {
        format!("{}.example.com", labels[0])
    } else if labels.len() == 2 {
        "example.com".to_string()
    } else {
        "example.invalid".to_string()
    }
}

pub(crate) fn stable_email_alias(value: &str) -> String {
    let local = value.split('@').next().unwrap_or("user");
    let alias = sanitize_label(local);
    if alias.is_empty() {
        "user@example.com".to_string()
    } else {
        format!("{alias}@example.com")
    }
}

pub(crate) fn stable_url_alias(value: &str) -> String {
    if let Ok(mut parsed) = Url::parse(value) {
        if let Some(host) = parsed.host_str() {
            let replacement = stable_domain_alias(host);
            if parsed.set_host(Some(&replacement)).is_ok() {
                return parsed.to_string();
            }
        }
    }

    format!("https://example.com/redacted/{}", short_digest(value))
}

pub(crate) fn stable_ip_alias(value: &str) -> String {
    if let Ok(net) = value.parse::<IpNet>() {
        return match net {
            IpNet::V4(v4) => {
                let octets = v4.network().octets();
                format!("198.51.100.{}/{}", (octets[3] % 200) + 1, v4.prefix_len())
            }
            IpNet::V6(v6) => format!(
                "2001:db8::{:x}/{}",
                v6.network().segments()[7],
                v6.prefix_len()
            ),
        };
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                Ipv4Addr::new(198, 51, 100, (octets[3] % 200) + 1).to_string()
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, segments[7]).to_string()
            }
        };
    }

    format!(
        "198.51.100.{}",
        (short_digest(value).as_bytes()[0] % 200) + 1
    )
}

pub(crate) fn stable_phone_alias(value: &str) -> String {
    let digits = value.chars().filter(char::is_ascii_digit).count();
    match digits {
        n if n >= 11 => "15500000000".to_string(),
        n if n >= 7 => "555-0000".to_string(),
        _ => "000-0000".to_string(),
    }
}

fn sanitize_label(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase()
}

fn short_digest(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..6])
}
