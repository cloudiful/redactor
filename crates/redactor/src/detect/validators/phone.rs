pub(crate) fn is_valid_phone(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || looks_like_date_time(trimmed) {
        return false;
    }

    let digits = trimmed.chars().filter(char::is_ascii_digit).count();
    if !(7..=15).contains(&digits) {
        return false;
    }

    let digits_only = trimmed.chars().all(|ch| ch.is_ascii_digit());
    !digits_only || digits <= 11
}

fn looks_like_date_time(value: &str) -> bool {
    let Some((date_part, time_part)) = split_date_time(value) else {
        return false;
    };

    is_date_like(date_part) && time_part.is_none_or(is_time_like)
}

fn split_date_time(value: &str) -> Option<(&str, Option<&str>)> {
    if let Some((date_part, time_part)) = value.split_once('T') {
        return Some((date_part.trim(), Some(time_part.trim())));
    }

    if let Some((date_part, time_part)) = value.split_once(' ') {
        return Some((date_part.trim(), Some(time_part.trim())));
    }

    Some((value.trim(), None))
}

fn is_date_like(value: &str) -> bool {
    let delimiter = if value.contains('-') {
        '-'
    } else if value.contains('/') {
        '/'
    } else {
        return false;
    };

    let mut parts = value.split(delimiter);
    let (Some(year), Some(month), Some(day), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };

    year.len() == 4
        && year.chars().all(|ch| ch.is_ascii_digit())
        && parse_bounded_u8(month, 1, 12).is_some()
        && parse_bounded_u8(day, 1, 31).is_some()
}

fn is_time_like(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return parse_bounded_u8(trimmed, 0, 23).is_some();
    }

    let mut parts = trimmed.split(':');
    let (Some(hour), Some(minute), second) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    parse_bounded_u8(hour, 0, 23).is_some()
        && parse_bounded_u8(minute, 0, 59).is_some()
        && second.is_none_or(|value| parse_bounded_u8(value, 0, 59).is_some())
}

fn parse_bounded_u8(value: &str, min: u8, max: u8) -> Option<u8> {
    if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }

    let parsed = value.parse::<u8>().ok()?;
    (min..=max).contains(&parsed).then_some(parsed)
}

#[cfg(test)]
mod tests {
    use super::is_valid_phone;

    #[test]
    fn rejects_dates_and_long_numeric_ids() {
        assert!(!is_valid_phone("000018310720"));
        assert!(!is_valid_phone("2022-04-22 11"));
        assert!(!is_valid_phone("2025-12-10 14"));
    }

    #[test]
    fn accepts_real_phone_formats() {
        assert!(is_valid_phone("15500000000"));
        assert!(is_valid_phone("+1 415-555-0123"));
    }
}
