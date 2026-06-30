use super::code_context::is_code_like_domain_context;

const PRIVATE_HOST_SUFFIXES: &[&str] = &["internal", "lan", "local", "localhost"];

pub(crate) fn looks_like_secret(value: &str) -> bool {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() < 20 || chars.len() > 128 {
        return false;
    }

    let has_upper = chars.iter().any(char::is_ascii_uppercase);
    let has_lower = chars.iter().any(char::is_ascii_lowercase);
    let has_digit = chars.iter().any(char::is_ascii_digit);
    let allowed = chars
        .iter()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '+'));

    allowed
        && has_digit
        && (has_upper || has_lower)
        && !(value.contains('.') || value.contains(':'))
}

pub(crate) fn is_valid_domain(value: &str) -> bool {
    if is_valid_email(value) || value.contains("://") || value.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }

    let normalized = value.trim().trim_end_matches('.');
    let labels = normalized.split('.').collect::<Vec<_>>();
    if labels.len() < 2 {
        return false;
    }

    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    }) && has_known_host_suffix(normalized)
}

pub(crate) fn is_valid_domain_match(text: &str, start: usize, end: usize) -> bool {
    let value = &text[start..end];
    if !is_valid_domain(value) {
        return false;
    }

    let previous = text[..start].chars().next_back();
    let next = text[end..].chars().next();
    if matches!(previous, Some('/' | '\\')) || matches!(next, Some('/' | '\\')) {
        return false;
    }

    !looks_like_file_name(value) && !is_code_like_domain_context(text, start, end)
}

pub(crate) fn is_valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.ends_with('.') {
        return false;
    }
    if !local.chars().all(is_email_local) {
        return false;
    }
    is_valid_domain(domain)
}

pub(crate) fn is_valid_cidr(value: &str) -> bool {
    value.parse::<ipnet::IpNet>().is_ok()
}

pub(crate) fn is_valid_ip(value: &str) -> bool {
    match value.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => !ip.is_unspecified(),
        Ok(std::net::IpAddr::V6(ip)) => !ip.is_unspecified() && is_substantial_ipv6(value),
        Err(_) => false,
    }
}

fn is_substantial_ipv6(value: &str) -> bool {
    if value.contains('.') {
        return true;
    }

    value
        .split(':')
        .filter(|segment| !segment.is_empty())
        .count()
        >= 4
}

pub(crate) fn is_email_local(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-')
}

pub(crate) fn is_email_domain(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-')
}

pub(super) fn has_known_host_suffix(value: &str) -> bool {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    if let Some(suffix) = psl::suffix(normalized.as_bytes())
        && suffix.is_known()
    {
        return true;
    }

    let Some(suffix) = normalized.rsplit('.').next() else {
        return false;
    };
    PRIVATE_HOST_SUFFIXES.contains(&suffix)
}

fn looks_like_file_name(value: &str) -> bool {
    let Some((name, extension)) = value.rsplit_once('.') else {
        return false;
    };
    if name.is_empty() || extension.is_empty() {
        return false;
    }

    matches!(
        extension.to_ascii_lowercase().as_str(),
        "c" | "cc"
            | "conf"
            | "config"
            | "cpp"
            | "csv"
            | "env"
            | "go"
            | "gradle"
            | "h"
            | "hpp"
            | "ini"
            | "java"
            | "js"
            | "json"
            | "jsx"
            | "kt"
            | "lock"
            | "md"
            | "php"
            | "properties"
            | "py"
            | "rb"
            | "rs"
            | "scss"
            | "sh"
            | "sql"
            | "swift"
            | "tf"
            | "toml"
            | "ts"
            | "tsx"
            | "txt"
            | "xml"
            | "yaml"
            | "yml"
    )
}

#[cfg(test)]
mod tests {
    use super::{is_valid_domain, is_valid_domain_match, is_valid_ip};

    #[test]
    fn rejects_unknown_suffix_member_access_chains() {
        assert!(!is_valid_domain("data.put"));
        assert!(!is_valid_domain("generator.generatePdf"));
        assert!(!is_valid_domain("list.add"));
    }

    #[test]
    fn accepts_real_domains_and_rejects_code_context_matches() {
        assert!(is_valid_domain("service.example.co.uk"));
        assert!(is_valid_domain("prod.internal.example.com"));
        assert!(!is_valid_domain_match(
            "let x = artifact.result.stats;",
            8,
            29
        ));
    }

    #[test]
    fn rejects_unspecified_ip_literals_used_as_scope_separators() {
        assert!(!is_valid_ip("::"));
        assert!(!is_valid_ip("0.0.0.0"));
        assert!(!is_valid_ip("f32::"));
        assert!(!is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip("fe80::1"));
        assert!(is_valid_ip("2001:db8:1:2::1"));
        assert!(is_valid_ip("::ffff:192.168.1.10"));
    }
}
