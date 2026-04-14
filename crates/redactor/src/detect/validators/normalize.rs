use crate::types::FindingKind;

pub(crate) fn normalize(kind: FindingKind, value: &str) -> String {
    match kind {
        FindingKind::Domain => value.trim().trim_matches('.').to_ascii_lowercase(),
        FindingKind::Email => value.trim().to_ascii_lowercase(),
        FindingKind::Url => value.trim().to_string(),
        FindingKind::Ip | FindingKind::Cidr | FindingKind::Phone | FindingKind::Secret => {
            value.trim().to_string()
        }
        FindingKind::Person | FindingKind::Organization => {
            value.split_whitespace().collect::<Vec<_>>().join(" ")
        }
    }
}

pub(crate) fn trim_wrapped(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}
