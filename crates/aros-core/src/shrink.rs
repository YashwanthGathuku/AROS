//! Delta debugging (Zeller). Minimize a failing input. No LLM.

/// Shrink `input` while `still_fails` remains true. Returns a 1-minimal slice.
pub fn shrink_bytes(input: &[u8], still_fails: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    if input.is_empty() || !still_fails(input) {
        return input.to_vec();
    }
    let mut current = input.to_vec();
    let mut chunk = current.len().max(1);
    while chunk > 0 {
        let mut progressed = false;
        let mut offset = 0;
        while offset < current.len() {
            let end = (offset + chunk).min(current.len());
            let mut candidate = Vec::with_capacity(current.len() - (end - offset));
            candidate.extend_from_slice(&current[..offset]);
            candidate.extend_from_slice(&current[end..]);
            if !candidate.is_empty() && still_fails(&candidate) {
                current = candidate;
                progressed = true;
            } else {
                offset = end;
            }
        }
        if !progressed {
            chunk /= 2;
        }
    }
    current
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn shrinks_to_the_nul_that_triggers() {
        let input = [b'A', b'A', 0, b'B', b'B'];
        let shrunk = shrink_bytes(&input, |bytes| bytes.contains(&0));
        assert_eq!(shrunk, vec![0]);
    }

    #[test]
    fn leaves_passing_input_alone() {
        let input = b"ok";
        let shrunk = shrink_bytes(input, |_| false);
        assert_eq!(shrunk, b"ok");
    }
}
