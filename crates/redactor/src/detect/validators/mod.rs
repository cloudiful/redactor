mod code_context;
mod domain;
mod normalize;
mod phone;

pub(crate) use code_context::{is_likely_code_expression, is_plain_config_value};
pub(crate) use domain::{
    is_email_domain, is_email_local, is_valid_cidr, is_valid_domain, is_valid_domain_match,
    is_valid_email, is_valid_ip, looks_like_secret,
};
pub(crate) use normalize::{normalize, trim_wrapped};
pub(crate) use phone::is_valid_phone;
