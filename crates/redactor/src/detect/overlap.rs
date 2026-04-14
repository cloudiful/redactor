use crate::types::Finding;

pub(crate) fn select_non_overlapping(mut findings: Vec<Finding>) -> (Vec<Finding>, usize) {
    findings.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.score().cmp(&left.score()))
            .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
    });

    let mut selected = Vec::new();
    let mut dropped = 0;

    for finding in findings {
        if let Some(previous) = selected.last_mut() {
            if overlaps(previous, &finding) {
                if prefer_right(previous, &finding) {
                    *previous = finding;
                } else {
                    dropped += 1;
                }
                continue;
            }
        }

        selected.push(finding);
    }

    selected.sort_by_key(|item| item.start);
    (selected, dropped)
}

fn overlaps(left: &Finding, right: &Finding) -> bool {
    left.start < right.end && right.start < left.end
}

fn prefer_right(left: &Finding, right: &Finding) -> bool {
    let left_contains_right = left.start <= right.start && left.end >= right.end;
    let right_contains_left = right.start <= left.start && right.end >= left.end;

    if left_contains_right || right_contains_left {
        let left_priority = left.kind.containment_priority();
        let right_priority = right.kind.containment_priority();
        if left_priority != right_priority {
            return right_priority > left_priority;
        }
    }

    right.score() > left.score()
        || (right.score() == left.score() && (right.end - right.start) > (left.end - left.start))
}
