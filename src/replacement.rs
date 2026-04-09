use crate::types::{
    AppliedReplacement, Finding, FindingKind, ReplacementEngine, ReplacementStrategy,
};
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

pub fn apply_replacements(text: &str, findings: &[Finding]) -> (String, Vec<AppliedReplacement>) {
    let mut engine = ReplacementEngine::new();
    let mut output = String::with_capacity(text.len());
    let mut applied = Vec::new();
    let mut cursor = 0;

    for finding in findings {
        output.push_str(&text[cursor..finding.start]);
        let replacement = replacement_for(&mut engine, finding);
        output.push_str(&replacement.replacement);
        applied.push(replacement);
        cursor = finding.end;
    }

    output.push_str(&text[cursor..]);
    (output, applied)
}

fn replacement_for(engine: &mut ReplacementEngine, finding: &Finding) -> AppliedReplacement {
    let normalized = finding.normalized_key.clone();
    let map = engine.map_mut(finding.kind);

    if let Some(existing) = map.get(&normalized) {
        return AppliedReplacement {
            kind: finding.kind,
            original: finding.match_text.clone(),
            replacement: existing.clone(),
            strategy: strategy_for(finding.kind),
        };
    }

    let replacement = match finding.kind {
        FindingKind::Secret | FindingKind::Person | FindingKind::Organization => {
            stable_secret_placeholder(map.len() + 1)
        }
        FindingKind::Domain => stable_domain_alias(&finding.match_text),
        FindingKind::Email => stable_email_alias(&finding.match_text, map.len() + 1),
        FindingKind::Url => stable_url_alias(&finding.match_text),
        FindingKind::Ip | FindingKind::Cidr => stable_ip_alias(&finding.match_text),
        FindingKind::Phone => stable_phone_alias(&finding.match_text, map.len() + 1),
    };

    map.insert(normalized, replacement.clone());

    AppliedReplacement {
        kind: finding.kind,
        original: finding.match_text.clone(),
        replacement,
        strategy: strategy_for(finding.kind),
    }
}

fn strategy_for(kind: FindingKind) -> ReplacementStrategy {
    match kind {
        FindingKind::Secret | FindingKind::Person | FindingKind::Organization => {
            ReplacementStrategy::StablePlaceholder
        }
        FindingKind::Domain => ReplacementStrategy::StableExampleDomain,
        FindingKind::Email => ReplacementStrategy::StableExampleEmail,
        FindingKind::Url => ReplacementStrategy::StableUrlRewrite,
        FindingKind::Ip | FindingKind::Cidr => ReplacementStrategy::StableIpRewrite,
        FindingKind::Phone => ReplacementStrategy::StablePhoneMask,
    }
}

fn stable_secret_placeholder(index: usize) -> String {
    format!("<SECRET:{index}>")
}

fn stable_domain_alias(value: &str) -> String {
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() >= 3 {
        format!("{}.example.com", labels[0])
    } else if labels.len() == 2 {
        "example.com".to_string()
    } else {
        "example.invalid".to_string()
    }
}

fn stable_email_alias(value: &str, index: usize) -> String {
    let local = value.split('@').next().unwrap_or("user");
    let alias = sanitize_label(local);
    if alias.is_empty() {
        format!("user{index}@example.com")
    } else {
        format!("{alias}@example.com")
    }
}

fn stable_url_alias(value: &str) -> String {
    if let Ok(mut parsed) = Url::parse(value) {
        if let Some(host) = parsed.host_str() {
            let replacement = stable_domain_alias(host);
            if parsed.set_host(Some(&replacement)).is_ok() {
                return parsed.to_string();
            }
        }
    }

    let digest = short_digest(value);
    format!("https://example.com/redacted/{digest}")
}

fn stable_ip_alias(value: &str) -> String {
    if let Ok(net) = value.parse::<IpNet>() {
        return match net {
            IpNet::V4(v4) => {
                let network = v4.network();
                let octets = network.octets();
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

fn stable_phone_alias(value: &str, index: usize) -> String {
    let digits = value.chars().filter(char::is_ascii_digit).count();
    let tail = format!("{:04}", index % 10_000);
    match digits {
        n if n >= 11 => format!("1550000{tail}"),
        n if n >= 7 => format!("555-{tail}"),
        _ => format!("000-{tail}"),
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
