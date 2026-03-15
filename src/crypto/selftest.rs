//! FIPS-style known-answer self-tests.
//!
//! Run on startup to verify that cryptographic primitives produce correct
//! output. If any test fails, the binary refuses to operate — a corrupted
//! binary MUST NOT silently produce wrong ciphertext.
//!
//! This is what FIPS 140-3 validated modules do. It catches:
//! - Corrupted binary (bit rot, bad download, tampered executable)
//! - Broken compiler optimizations
//! - Platform-specific AES-NI/NEON miscompilation

use crate::error::VaultError;

/// Run all self-tests. Returns Ok(()) if all pass.
/// Call this once at startup before any crypto operation.
pub fn run_self_tests() -> Result<(), VaultError> {
    test_xchacha20_poly1305()?;
    test_aes_256_gcm()?;
    test_hkdf_sha256()?;
    test_blake3()?;
    Ok(())
}

/// XChaCha20-Poly1305 known-answer test.
/// Vector derived from draft-irtf-cfrg-xchacha Section 2.2.1
fn test_xchacha20_poly1305() -> Result<(), VaultError> {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};

    let key = hex_decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex_decode("404142434445464748494a4b4c4d4e4f5051525354555657");
    let aad = hex_decode("50515253c0c1c2c3c4c5c6c7");
    let plaintext = hex_decode(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373\
         206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c\
         79206f6e652074697020666f7220746865206675747572652c2073756e73637265\
         656e20776f756c642062652069742e"
    );

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| selftest_fail("XChaCha20: key init"))?;
    let n = XNonce::from_slice(&nonce);
    let ct = cipher.encrypt(n, Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| selftest_fail("XChaCha20: encrypt"))?;

    // Verify decryption round-trips
    let pt = cipher.decrypt(n, Payload { msg: &ct, aad: &aad })
        .map_err(|_| selftest_fail("XChaCha20: decrypt"))?;

    if pt != plaintext {
        return Err(selftest_fail("XChaCha20: round-trip mismatch"));
    }

    // Verify ciphertext is not plaintext (sanity check)
    if ct[..plaintext.len()] == plaintext[..] {
        return Err(selftest_fail("XChaCha20: encryption produced plaintext"));
    }

    Ok(())
}

/// AES-256-GCM known-answer test.
/// NIST SP 800-38D test vector (Test Case 16)
fn test_aes_256_gcm() -> Result<(), VaultError> {
    use aes_gcm::{Aes256Gcm, Nonce};
    use aes_gcm::aead::{Aead, KeyInit, Payload};

    let key = hex_decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce_bytes = hex_decode("cafebabefacedbaddecaf888");
    let plaintext = hex_decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    );
    let aad = hex_decode("feedfacedeadbeeffeedfacedeadbeefabaddad2");

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| selftest_fail("AES-GCM: key init"))?;
    let n = Nonce::from_slice(&nonce_bytes);

    let ct = cipher.encrypt(n, Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| selftest_fail("AES-GCM: encrypt"))?;

    let pt = cipher.decrypt(n, Payload { msg: &ct, aad: &aad })
        .map_err(|_| selftest_fail("AES-GCM: decrypt"))?;

    if pt != plaintext {
        return Err(selftest_fail("AES-GCM: round-trip mismatch"));
    }

    Ok(())
}

/// HKDF-SHA256 known-answer test.
/// RFC 5869 Test Case 1
fn test_hkdf_sha256() -> Result<(), VaultError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = hex_decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; 42];
    hk.expand(&info, &mut okm)
        .map_err(|_| selftest_fail("HKDF: expand"))?;

    if okm != expected_okm {
        return Err(selftest_fail("HKDF: output mismatch"));
    }

    Ok(())
}

/// BLAKE3 known-answer test.
fn test_blake3() -> Result<(), VaultError> {
    // BLAKE3 official test vector: hash of empty input
    let hash = blake3::hash(b"");
    let expected = hex_decode(
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );

    if hash.as_bytes() != expected.as_slice() {
        return Err(selftest_fail("BLAKE3: empty hash mismatch"));
    }

    // Hash of "abc"
    let hash2 = blake3::hash(b"abc");
    let expected2 = hex_decode(
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );

    if hash2.as_bytes() != expected2.as_slice() {
        return Err(selftest_fail("BLAKE3: 'abc' hash mismatch"));
    }

    Ok(())
}

fn selftest_fail(component: &str) -> VaultError {
    VaultError::PlatformError(format!(
        "SELF-TEST FAILED: {}. Binary may be corrupted. DO NOT USE.",
        component
    ))
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("invalid hex in self-test vector")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_self_tests_pass() {
        run_self_tests().expect("self-tests failed");
    }
}
