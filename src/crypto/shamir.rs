//! Shamir Secret Sharing — split a key into N shares, any K reconstruct it.
//!
//! Used for key recovery: distribute shares to trusted parties so that
//! no single party can decrypt, but any K cooperating can.

use sharks::{Share, Sharks};
use crate::error::VaultError;
use crate::memory::SecureBuf;

/// Split a secret into `total` shares, any `threshold` of which can reconstruct it.
///
/// - `threshold` (K): minimum shares needed (must be >= 2)
/// - `total` (N): total shares generated (must be >= threshold)
pub fn split(
    secret: &SecureBuf,
    threshold: u8,
    total: u8,
) -> Result<Vec<Vec<u8>>, VaultError> {
    if threshold < 2 {
        return Err(VaultError::InvalidShamirParams(
            "threshold must be >= 2 (single-share defeats the purpose)".into(),
        ));
    }
    if total < threshold {
        return Err(VaultError::InvalidShamirParams(
            "total shares must be >= threshold".into(),
        ));
    }
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret.expose());

    let shares: Vec<Vec<u8>> = dealer
        .take(total as usize)
        .map(|share| Vec::from(&share))
        .collect();

    Ok(shares)
}

/// Reconstruct a secret from K or more shares.
pub fn combine(shares: &[Vec<u8>]) -> Result<SecureBuf, VaultError> {
    if shares.is_empty() {
        return Err(VaultError::ShareRecoveryFailed);
    }

    let parsed: Vec<Share> = shares
        .iter()
        .map(|s| Share::try_from(s.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| VaultError::InvalidShare)?;

    let secret = Sharks(parsed.len() as u8)
        .recover(&parsed)
        .map_err(|_| VaultError::ShareRecoveryFailed)?;

    SecureBuf::from_slice(&secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_combine_3_of_5() {
        let secret = SecureBuf::from_slice(b"my secret 32-byte key material!!").unwrap();
        let shares = split(&secret, 3, 5).unwrap();

        assert_eq!(shares.len(), 5);

        // Any 3 shares should reconstruct
        let recovered = combine(&shares[0..3]).unwrap();
        assert_eq!(recovered.expose(), secret.expose());

        // Different 3 shares should also work
        let recovered2 = combine(&shares[2..5]).unwrap();
        assert_eq!(recovered2.expose(), secret.expose());
    }

    #[test]
    fn test_threshold_too_low() {
        let secret = SecureBuf::from_slice(b"key").unwrap();
        assert!(split(&secret, 1, 3).is_err());
    }

    #[test]
    fn test_total_less_than_threshold() {
        let secret = SecureBuf::from_slice(b"key").unwrap();
        assert!(split(&secret, 5, 3).is_err());
    }
}
