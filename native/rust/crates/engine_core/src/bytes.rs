//! Bounded byte-buffer primitives.
//!
//! Every function here enforces an explicit size limit before it allocates or
//! scans, so a hostile or malformed input cannot drive unbounded work. The
//! comparison helper is constant-time because a naive `==` on a signature or
//! token leaks the position of the first differing byte through timing.

use crate::{EngineError, Result};

/// Largest buffer these helpers will process, in bytes (1 MiB).
pub const MAX_BUFFER_BYTES: usize = 1024 * 1024;

/// Compare two byte slices in time independent of their contents.
///
/// Length inequality returns `false` immediately: lengths are not secret, and
/// comparing different-length inputs cannot be made meaningfully uniform.
/// For equal lengths every byte is examined regardless of early mismatches.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Reject a buffer that exceeds [`MAX_BUFFER_BYTES`].
///
/// # Errors
/// Returns [`EngineError::InputTooLarge`] when the buffer is over the limit.
pub fn check_bounds(data: &[u8]) -> Result<()> {
    if data.len() > MAX_BUFFER_BYTES {
        return Err(EngineError::InputTooLarge {
            actual: data.len(),
            limit: MAX_BUFFER_BYTES,
        });
    }
    Ok(())
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
///
/// # Errors
/// Returns [`EngineError::EmptyInput`] for an empty needle (which would match
/// infinitely), [`EngineError::InvalidPattern`] when the needle is longer than
/// the haystack, and [`EngineError::InputTooLarge`] beyond the size bound.
pub fn count_occurrences(haystack: &[u8], needle: &[u8]) -> Result<usize> {
    check_bounds(haystack)?;
    if needle.is_empty() {
        return Err(EngineError::EmptyInput);
    }
    if needle.len() > haystack.len() {
        return Err(EngineError::InvalidPattern);
    }
    let mut count = 0usize;
    let mut index = 0usize;
    while index + needle.len() <= haystack.len() {
        if &haystack[index..index + needle.len()] == needle {
            count += 1;
            index += needle.len();
        } else {
            index += 1;
        }
    }
    Ok(count)
}

/// Return the index of the first occurrence of `needle`, if any.
///
/// # Errors
/// Same conditions as [`count_occurrences`].
pub fn find_first(haystack: &[u8], needle: &[u8]) -> Result<Option<usize>> {
    check_bounds(haystack)?;
    if needle.is_empty() {
        return Err(EngineError::EmptyInput);
    }
    if needle.len() > haystack.len() {
        return Ok(None);
    }
    for index in 0..=(haystack.len() - needle.len()) {
        if &haystack[index..index + needle.len()] == needle {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// Shannon entropy of a buffer in bits per byte, from 0.0 to 8.0.
///
/// High entropy in a source file is a useful *signal* for secret detection —
/// not a verdict. Callers must treat the value as one input to a rule, never
/// as proof that a string is a credential.
///
/// # Errors
/// Returns [`EngineError::EmptyInput`] for an empty buffer, since entropy is
/// undefined there, and [`EngineError::InputTooLarge`] beyond the bound.
pub fn shannon_entropy(data: &[u8]) -> Result<f64> {
    check_bounds(data)?;
    if data.is_empty() {
        return Err(EngineError::EmptyInput);
    }
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in counts.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total;
        entropy -= p * p.log2();
    }
    Ok(entropy)
}

/// Render a buffer as lowercase hexadecimal.
///
/// # Errors
/// Returns [`EngineError::InputTooLarge`] beyond the bound.
pub fn to_hex(data: &[u8]) -> Result<String> {
    check_bounds(data)?;
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equality_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_examines_every_byte_of_equal_length_inputs() {
        // Differing only in the last byte must still return false; an early
        // return would make this pass for the wrong reason.
        assert!(!constant_time_eq(b"aaaaaaaa", b"aaaaaaab"));
        assert!(!constant_time_eq(b"baaaaaaa", b"aaaaaaaa"));
    }

    #[test]
    fn bounds_are_enforced() {
        let oversized = vec![0u8; MAX_BUFFER_BYTES + 1];
        assert_eq!(
            check_bounds(&oversized),
            Err(EngineError::InputTooLarge {
                actual: MAX_BUFFER_BYTES + 1,
                limit: MAX_BUFFER_BYTES
            })
        );
        assert!(check_bounds(&vec![0u8; MAX_BUFFER_BYTES]).is_ok());
    }

    #[test]
    fn counts_non_overlapping_occurrences() {
        assert_eq!(count_occurrences(b"aaaa", b"aa").unwrap(), 2);
        assert_eq!(count_occurrences(b"abcabc", b"abc").unwrap(), 2);
        assert_eq!(count_occurrences(b"abc", b"z").unwrap(), 0);
    }

    #[test]
    fn empty_needle_is_rejected_rather_than_looping() {
        assert_eq!(count_occurrences(b"abc", b""), Err(EngineError::EmptyInput));
        assert_eq!(find_first(b"abc", b""), Err(EngineError::EmptyInput));
    }

    #[test]
    fn needle_longer_than_haystack_is_handled() {
        assert_eq!(
            count_occurrences(b"ab", b"abc"),
            Err(EngineError::InvalidPattern)
        );
        assert_eq!(find_first(b"ab", b"abc").unwrap(), None);
    }

    #[test]
    fn finds_first_index() {
        assert_eq!(find_first(b"hello world", b"world").unwrap(), Some(6));
        assert_eq!(find_first(b"hello", b"z").unwrap(), None);
    }

    #[test]
    fn entropy_is_zero_for_uniform_data_and_eight_for_all_bytes() {
        let uniform = vec![b'A'; 128];
        assert!(shannon_entropy(&uniform).unwrap().abs() < 1e-9);

        let all: Vec<u8> = (0..=255u8).collect();
        assert!((shannon_entropy(&all).unwrap() - 8.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_rejects_empty_input() {
        assert_eq!(shannon_entropy(b""), Err(EngineError::EmptyInput));
    }

    #[test]
    fn hex_encoding_is_lowercase_and_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]).unwrap(), "000fff");
        assert_eq!(to_hex(b"").unwrap(), "");
    }
}
