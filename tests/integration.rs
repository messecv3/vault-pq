//! End-to-end integration tests for the Vault library.
//!
//! All tests use tempdir() — no real user paths are touched.

use vault::crypto::{aead, kdf, kem, stream};
use vault::format::{header, padding};
use vault::memory::SecureBuf;

/// Full encrypt → decrypt round-trip using passphrase.
#[test]
fn test_passphrase_round_trip() {
    let plaintext = b"The quick brown fox jumps over the lazy dog.";
    let passphrase = b"correct horse battery staple";

    // --- Encrypt ---
    let file_key = SecureBuf::random(32).unwrap();
    let algorithm = aead::AeadAlgorithm::XChaCha20Poly1305;
    let salt = kdf::generate_salt();
    let params = kdf::KdfParams::low();

    let derived = kdf::derive_key(passphrase.to_vec(), &salt, &params).unwrap();
    let encrypted_fk = header::wrap_file_key_passphrase(&derived, &file_key).unwrap();

    let stanza = header::RecipientStanza::Passphrase {
        salt,
        params,
        encrypted_file_key: encrypted_fk,
    };

    // Encrypt body
    let mut body = Vec::new();
    let hash = stream::encrypt_stream(
        &mut &plaintext[..],
        &mut body,
        &file_key,
        algorithm,
        stream::DEFAULT_CHUNK_SIZE,
    ).unwrap();

    let metadata = header::EncryptedMetadata {
        algorithm,
        chunk_size: stream::DEFAULT_CHUNK_SIZE as u32,
        original_filename: Some("test.txt".into()),
        original_size: plaintext.len() as u64,
        padding_bucket: 0xFF,
        plaintext_hash: Some(hash),
        signature: None,
    };

    // Write full file
    let mut vault_file = Vec::new();
    header::write_file_header(&mut vault_file, &[stanza], &metadata, &file_key).unwrap();
    vault_file.extend_from_slice(&body);

    // --- Decrypt ---
    let mut cursor = std::io::Cursor::new(&vault_file);

    // Read stanzas
    let (stanzas, magic) = header::read_stanzas(&mut cursor).unwrap();
    assert_eq!(stanzas.len(), 1);

    // Recover file key
    let recovered_key = stanzas[0].try_unwrap_passphrase(passphrase).unwrap();
    assert_eq!(recovered_key.expose(), file_key.expose());

    // Read metadata
    let recovered_meta = header::read_metadata(&mut cursor, &recovered_key, &magic).unwrap();
    assert_eq!(recovered_meta.original_filename, Some("test.txt".into()));
    assert_eq!(recovered_meta.original_size, plaintext.len() as u64);

    // Decrypt body
    let body_start = cursor.position() as usize;
    let body_data = &vault_file[body_start..];

    let mut decrypted = Vec::new();
    let dec_hash = stream::decrypt_stream(
        &mut &body_data[..],
        &mut decrypted,
        &recovered_key,
        recovered_meta.algorithm,
        recovered_meta.chunk_size as usize,
    ).unwrap();

    // Verify
    assert_eq!(&decrypted, plaintext);
    assert_eq!(dec_hash, hash);
    assert_eq!(recovered_meta.plaintext_hash, Some(dec_hash));
}

/// Full encrypt → decrypt round-trip using public key.
#[test]
fn test_public_key_round_trip() {
    let plaintext = b"Hybrid post-quantum encryption works!";

    // Generate keypair
    let (pk, sk) = kem::generate_keypair();

    // Encrypt
    let file_key = SecureBuf::random(32).unwrap();
    let algorithm = aead::AeadAlgorithm::XChaCha20Poly1305;

    let (shared_secret, encap) = kem::encapsulate(&pk).unwrap();
    let encrypted_fk = header::wrap_file_key_public(&shared_secret, &file_key).unwrap();

    let stanza = header::RecipientStanza::PublicKey {
        encap_data: encap.to_bytes(),
        encrypted_file_key: encrypted_fk,
    };

    let mut body = Vec::new();
    let hash = stream::encrypt_stream(
        &mut &plaintext[..],
        &mut body,
        &file_key,
        algorithm,
        stream::DEFAULT_CHUNK_SIZE,
    ).unwrap();

    let metadata = header::EncryptedMetadata {
        algorithm,
        chunk_size: stream::DEFAULT_CHUNK_SIZE as u32,
        original_filename: None,
        original_size: plaintext.len() as u64,
        padding_bucket: 0xFF,
        plaintext_hash: Some(hash),
        signature: None,
    };

    let mut vault_file = Vec::new();
    header::write_file_header(&mut vault_file, &[stanza], &metadata, &file_key).unwrap();
    vault_file.extend_from_slice(&body);

    // Decrypt
    let mut cursor = std::io::Cursor::new(&vault_file);
    let (stanzas, magic) = header::read_stanzas(&mut cursor).unwrap();

    let recovered_key = stanzas[0].try_unwrap_public_key(&sk).unwrap();
    let recovered_meta = header::read_metadata(&mut cursor, &recovered_key, &magic).unwrap();

    let body_start = cursor.position() as usize;
    let mut decrypted = Vec::new();
    stream::decrypt_stream(
        &mut &vault_file[body_start..],
        &mut decrypted,
        &recovered_key,
        recovered_meta.algorithm,
        recovered_meta.chunk_size as usize,
    ).unwrap();

    assert_eq!(&decrypted, plaintext);
}

/// Wrong passphrase must fail.
#[test]
fn test_wrong_passphrase_fails() {
    let file_key = SecureBuf::random(32).unwrap();
    let salt = kdf::generate_salt();
    let params = kdf::KdfParams::low();

    let derived = kdf::derive_key(b"correct".to_vec(), &salt, &params).unwrap();
    let encrypted_fk = header::wrap_file_key_passphrase(&derived, &file_key).unwrap();

    let stanza = header::RecipientStanza::Passphrase {
        salt,
        params,
        encrypted_file_key: encrypted_fk,
    };

    let result = stanza.try_unwrap_passphrase(b"wrong");
    assert!(result.is_err());
}

/// Wrong private key must fail.
#[test]
fn test_wrong_private_key_fails() {
    let (pk1, _sk1) = kem::generate_keypair();
    let (_pk2, sk2) = kem::generate_keypair();

    let file_key = SecureBuf::random(32).unwrap();
    let (shared_secret, encap) = kem::encapsulate(&pk1).unwrap();
    let encrypted_fk = header::wrap_file_key_public(&shared_secret, &file_key).unwrap();

    let stanza = header::RecipientStanza::PublicKey {
        encap_data: encap.to_bytes(),
        encrypted_file_key: encrypted_fk,
    };

    // Decapsulation with wrong key produces a different shared secret,
    // which then fails to unwrap the file key (auth tag mismatch).
    let result = stanza.try_unwrap_public_key(&sk2);
    assert!(result.is_err());
}

/// Multi-recipient: passphrase + public key, either can decrypt.
#[test]
fn test_multi_recipient() {
    let plaintext = b"accessible to both recipients";
    let file_key = SecureBuf::random(32).unwrap();
    let algorithm = aead::AeadAlgorithm::XChaCha20Poly1305;

    // Recipient 1: passphrase
    let salt = kdf::generate_salt();
    let params = kdf::KdfParams::low();
    let derived = kdf::derive_key(b"passphrase".to_vec(), &salt, &params).unwrap();
    let efk1 = header::wrap_file_key_passphrase(&derived, &file_key).unwrap();
    let stanza1 = header::RecipientStanza::Passphrase {
        salt, params, encrypted_file_key: efk1,
    };

    // Recipient 2: public key
    let (pk, sk) = kem::generate_keypair();
    let (ss, encap) = kem::encapsulate(&pk).unwrap();
    let efk2 = header::wrap_file_key_public(&ss, &file_key).unwrap();
    let stanza2 = header::RecipientStanza::PublicKey {
        encap_data: encap.to_bytes(),
        encrypted_file_key: efk2,
    };

    // Encrypt
    let mut body = Vec::new();
    let hash = stream::encrypt_stream(
        &mut &plaintext[..], &mut body, &file_key, algorithm, 64,
    ).unwrap();

    let metadata = header::EncryptedMetadata {
        algorithm,
        chunk_size: 64,
        original_filename: None,
        original_size: plaintext.len() as u64,
        padding_bucket: 0xFF,
        plaintext_hash: Some(hash),
        signature: None,
    };

    let mut vault_file = Vec::new();
    header::write_file_header(
        &mut vault_file, &[stanza1, stanza2], &metadata, &file_key
    ).unwrap();
    vault_file.extend_from_slice(&body);

    // Decrypt with passphrase
    let mut c1 = std::io::Cursor::new(&vault_file);
    let (s1, m1) = header::read_stanzas(&mut c1).unwrap();
    assert_eq!(s1.len(), 2);
    let fk1 = s1[0].try_unwrap_passphrase(b"passphrase").unwrap();
    let meta1 = header::read_metadata(&mut c1, &fk1, &m1).unwrap();
    let mut dec1 = Vec::new();
    stream::decrypt_stream(
        &mut &vault_file[c1.position() as usize..],
        &mut dec1, &fk1, meta1.algorithm, meta1.chunk_size as usize,
    ).unwrap();
    assert_eq!(&dec1, plaintext);

    // Decrypt with public key
    let mut c2 = std::io::Cursor::new(&vault_file);
    let (s2, m2) = header::read_stanzas(&mut c2).unwrap();
    let fk2 = s2[1].try_unwrap_public_key(&sk).unwrap();
    let meta2 = header::read_metadata(&mut c2, &fk2, &m2).unwrap();
    let mut dec2 = Vec::new();
    stream::decrypt_stream(
        &mut &vault_file[c2.position() as usize..],
        &mut dec2, &fk2, meta2.algorithm, meta2.chunk_size as usize,
    ).unwrap();
    assert_eq!(&dec2, plaintext);
}

/// Padding must hide original file size.
#[test]
fn test_padding_hides_size() {
    let small = b"tiny";   // 4 bytes → 1KB bucket
    let medium = b"a]".repeat(2000); // 4000 bytes → 4KB bucket

    let (bucket_s, padded_s) = padding::select_bucket(small.len() as u64);
    let (bucket_m, padded_m) = padding::select_bucket(medium.len() as u64);

    assert_eq!(padded_s, 1024);
    assert_eq!(padded_m, 4096);
    assert_ne!(bucket_s, bucket_m);

    // Padding bytes are random (not zeros)
    let pad = padding::generate_padding(small.len(), padded_s);
    assert_eq!(pad.len(), 1020);
    assert!(!pad.iter().all(|&b| b == 0));
}

/// Tampered ciphertext must be rejected.
#[test]
fn test_tampered_body_rejected() {
    let file_key = SecureBuf::random(32).unwrap();
    let algorithm = aead::AeadAlgorithm::XChaCha20Poly1305;
    let plaintext = b"tamper test";

    let mut encrypted = Vec::new();
    stream::encrypt_stream(
        &mut &plaintext[..], &mut encrypted, &file_key, algorithm, 64,
    ).unwrap();

    // Flip a byte in the middle
    let mid = encrypted.len() / 2;
    encrypted[mid] ^= 0xFF;

    let mut decrypted = Vec::new();
    let result = stream::decrypt_stream(
        &mut &encrypted[..], &mut decrypted, &file_key, algorithm, 64,
    );

    assert!(result.is_err());
}

/// Secure memory is properly zeroed (best-effort test).
#[test]
fn test_secure_buf_zeroed_after_drop() {
    // We can't directly observe the memory after drop, but we can verify
    // the drop implementation runs without panicking.
    let buf = SecureBuf::random(256).unwrap();
    assert_eq!(buf.len(), 256);
    assert!(!buf.expose().iter().all(|&b| b == 0)); // random, not zero
    drop(buf);
    // If we get here, drop ran successfully (zeroing + deallocation)
}

/// Constant-time comparison must work correctly.
#[test]
fn test_constant_time_comparison() {
    assert!(vault::memory::constant_time_eq(b"hello", b"hello"));
    assert!(!vault::memory::constant_time_eq(b"hello", b"hellp"));
    assert!(!vault::memory::constant_time_eq(b"hello", b"hell"));
    assert!(!vault::memory::constant_time_eq(b"", b"x"));
    assert!(vault::memory::constant_time_eq(b"", b""));
}
