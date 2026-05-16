use crate::types::{Finding, FindingKind};

use super::aliases::{
    stable_domain_alias, stable_email_alias, stable_ip_alias, stable_phone_alias, stable_url_alias,
};

pub(crate) fn display_hint(finding: &Finding) -> Option<String> {
    Some(match finding.kind {
        FindingKind::Secret | FindingKind::Person | FindingKind::Organization => {
            format!("<{}>", finding.kind.label())
        }
        FindingKind::Domain => stable_domain_alias(&finding.match_text),
        FindingKind::Email => stable_email_alias(&finding.match_text),
        FindingKind::Url => stable_url_alias(&finding.match_text),
        FindingKind::Ip | FindingKind::Cidr => stable_ip_alias(&finding.match_text),
        FindingKind::Phone => stable_phone_alias(&finding.match_text),
        FindingKind::CustomString => format!("<{}>", finding.kind.label()),
        FindingKind::CustomFile => format!("<{}>", finding.kind.label()),
    })
}
