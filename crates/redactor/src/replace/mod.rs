mod aliases;
mod hints;
mod processor;
mod token;

pub(crate) use processor::ReplacementProcessor;
pub(crate) use token::{
    TOKEN_PREFIX, TOKEN_SUFFIX, format_token, parse_token, random_id, random_scope_id, sha256_hex,
    token_like_ranges,
};
