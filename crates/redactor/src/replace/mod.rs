mod aliases;
mod hints;
mod processor;
mod token;

pub(crate) use processor::ReplacementProcessor;
pub(crate) use token::{
    MAX_TOKEN_CANDIDATE_BYTES, TOKEN_PREFIX, TOKEN_SUFFIX, format_token, parse_token, random_id,
    random_scope_id, scan_token_like_ranges, sha256_hex,
};
