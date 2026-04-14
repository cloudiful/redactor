use regex::Regex;
use std::sync::OnceLock;

pub(crate) fn assignment_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"^\s*(?:-\s*)?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*(?P<separator>[:=])\s*(?P<value>[^\n#]+?)\s*$",
        )
        .expect("assignment regex")
    })
}

pub(crate) fn url_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"\bhttps?://[^\s'"<>]+"#).expect("url regex"))
}

pub(crate) fn cidr_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|\b[0-9A-Fa-f:]+/[0-9]{1,3}\b")
            .expect("cidr regex")
    })
}

pub(crate) fn ip_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
            .expect("ip regex")
    })
}

pub(crate) fn domain_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
            .expect("domain regex")
    })
}

pub(crate) fn secret_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"\b[A-Za-z0-9_+\-/]{20,128}\b").expect("secret regex"))
}
