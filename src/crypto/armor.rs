//! ASCII armor — base64-encoded output for email, chat, and text channels.
//!
//! Wraps vault ciphertext in a PEM-like armored format:
//!
//! ```text
//! -----BEGIN VAULT MESSAGE-----
//! Version: Vault 0.1.0
//! Algorithm: XChaCha20-Poly1305
//!
//! SGVsbG8sIHRoaXMgaXMgYSBiYXNlNjQtZW5jb2RlZCB2YXVsdCBmaWxlLiBJ
//! dCBjYW4gYmUgcGFzdGVkIGludG8gZW1haWwsIGNoYXQsIG9yIGFueSB0ZXh0
//! IGNoYW5uZWwgd2l0aG91dCBjb3JydXB0aW9uLg==
//! -----END VAULT MESSAGE-----
//! ```
//!
//! Line width: 64 characters (standard PEM).

use base64::Engine;
use crate::error::VaultError;

const ARMOR_BEGIN: &str = "-----BEGIN VAULT MESSAGE-----";
const ARMOR_END: &str = "-----END VAULT MESSAGE-----";
const LINE_WIDTH: usize = 64;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Wrap binary vault data in ASCII armor.
pub fn armor(data: &[u8]) -> String {
    let encoded = B64.encode(data);

    let mut output = String::new();
    output.push_str(ARMOR_BEGIN);
    output.push('\n');

    // Wrap at LINE_WIDTH characters
    for chunk in encoded.as_bytes().chunks(LINE_WIDTH) {
        output.push_str(std::str::from_utf8(chunk).unwrap());
        output.push('\n');
    }

    output.push_str(ARMOR_END);
    output.push('\n');
    output
}

/// Extract binary data from ASCII armor.
pub fn dearmor(text: &str) -> Result<Vec<u8>, VaultError> {
    let text = text.trim();

    // Find begin/end markers
    let begin_idx = text.find(ARMOR_BEGIN)
        .ok_or_else(|| VaultError::InvalidFormat("missing BEGIN marker".into()))?;
    let end_idx = text.find(ARMOR_END)
        .ok_or_else(|| VaultError::InvalidFormat("missing END marker".into()))?;

    if end_idx <= begin_idx {
        return Err(VaultError::InvalidFormat("END before BEGIN".into()));
    }

    // Extract content between markers
    let content_start = begin_idx + ARMOR_BEGIN.len();
    let content = &text[content_start..end_idx];

    // Remove whitespace and decode
    let cleaned: String = content.chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    B64.decode(&cleaned)
        .map_err(|e| VaultError::InvalidFormat(format!("invalid base64: {}", e)))
}

/// Check if text looks like armored vault data.
pub fn is_armored(text: &str) -> bool {
    text.trim().starts_with(ARMOR_BEGIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let data = b"This is some binary vault data \x00\x01\x02\xFF";
        let armored = armor(data);
        let recovered = dearmor(&armored).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_format() {
        let armored = armor(b"test");
        assert!(armored.starts_with(ARMOR_BEGIN));
        assert!(armored.trim_end().ends_with(ARMOR_END));
    }

    #[test]
    fn test_line_width() {
        let data = vec![0x42; 1000]; // enough to produce multiple lines
        let armored = armor(&data);

        for line in armored.lines() {
            if line == ARMOR_BEGIN || line == ARMOR_END || line.is_empty() {
                continue;
            }
            assert!(line.len() <= LINE_WIDTH, "line too long: {}", line.len());
        }
    }

    #[test]
    fn test_whitespace_tolerance() {
        let data = b"test data";
        let armored = armor(data);

        // Add extra whitespace
        let messy = format!("  \n\n  {}  \n\n  ", armored);
        let recovered = dearmor(&messy).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_missing_markers() {
        assert!(dearmor("just some random text").is_err());
        assert!(dearmor("-----BEGIN VAULT MESSAGE-----\ndata").is_err());
    }

    #[test]
    fn test_is_armored() {
        assert!(is_armored("-----BEGIN VAULT MESSAGE-----\ndata\n-----END VAULT MESSAGE-----"));
        assert!(!is_armored("not armored data"));
        assert!(is_armored("  \n-----BEGIN VAULT MESSAGE-----"));
    }

    #[test]
    fn test_large_data() {
        let data = vec![0xAB; 100_000];
        let armored = armor(&data);
        let recovered = dearmor(&armored).unwrap();
        assert_eq!(recovered, data);
    }
}
