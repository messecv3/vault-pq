//! `vault bench` — benchmark cryptographic operations.
//!
//! Reports throughput for each algorithm and operation.
//! Useful for hardware capability verification and performance tuning.

use std::time::Instant;
use crate::crypto::{aead, kdf, kem, stream};
use crate::memory::SecureBuf;
use crate::error::VaultError;

pub fn run() -> Result<(), VaultError> {
    crate::crypto::selftest::run_self_tests()?;
    eprintln!("Self-tests passed.\n");

    eprintln!("=== Vault Crypto Benchmark ===");
    eprintln!("Platform: {}", std::env::consts::ARCH);
    crate::platform::hardware::print_capabilities();
    eprintln!();

    bench_aead()?;
    bench_kdf()?;
    bench_kem()?;
    bench_streaming()?;
    bench_hashing()?;

    Ok(())
}

fn bench_aead() -> Result<(), VaultError> {
    eprintln!("--- AEAD Throughput ---");

    for algo in &[aead::AeadAlgorithm::XChaCha20Poly1305, aead::AeadAlgorithm::Aes256Gcm] {
        let key = SecureBuf::random(32)?;
        let nonce_size = algo.nonce_size();
        let mut nonce = vec![0u8; nonce_size];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let data = vec![0x42u8; 1_048_576]; // 1 MB
        let iterations = 50;

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = aead::encrypt(*algo, &key, &nonce, b"bench", &data)?;
        }
        let elapsed = start.elapsed();

        let mb_per_sec = (iterations as f64 * data.len() as f64) / elapsed.as_secs_f64() / 1_048_576.0;
        eprintln!("  {:?}: {:.0} MB/s (encrypt, 1MB blocks)", algo, mb_per_sec);
    }

    eprintln!();
    Ok(())
}

fn bench_kdf() -> Result<(), VaultError> {
    eprintln!("--- Key Derivation ---");

    let params = kdf::KdfParams {
        memory_kib: 65_536, // 64 MB for benchmark
        iterations: 3,
        parallelism: 4,
    };

    let salt = [0x42u8; 32];
    let start = Instant::now();
    let _ = kdf::derive_key(b"benchmark passphrase".to_vec(), &salt, &params)?;
    let elapsed = start.elapsed();

    eprintln!("  Argon2id (64MB, 3 iter, 4 threads): {:?}", elapsed);

    eprintln!();
    Ok(())
}

fn bench_kem() -> Result<(), VaultError> {
    eprintln!("--- Hybrid KEM (X25519 + ML-KEM-768) ---");

    let iterations = 20;

    // Keygen
    let start = Instant::now();
    let mut last_pk = None;
    let mut last_sk = None;
    for _ in 0..iterations {
        let (pk, sk) = kem::generate_keypair();
        last_pk = Some(pk);
        last_sk = Some(sk);
    }
    let elapsed = start.elapsed();
    eprintln!("  Keygen:       {:?}/op ({} ops)",
        elapsed / iterations, iterations);

    let pk = last_pk.unwrap();
    let sk = last_sk.unwrap();

    // Encapsulate
    let start = Instant::now();
    let mut last_encap = None;
    for _ in 0..iterations {
        let (_, encap) = kem::encapsulate(&pk)?;
        last_encap = Some(encap);
    }
    let elapsed = start.elapsed();
    eprintln!("  Encapsulate:  {:?}/op ({} ops)",
        elapsed / iterations, iterations);

    // Decapsulate
    let encap = last_encap.unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = kem::decapsulate(&sk, &encap)?;
    }
    let elapsed = start.elapsed();
    eprintln!("  Decapsulate:  {:?}/op ({} ops)",
        elapsed / iterations, iterations);

    eprintln!();
    Ok(())
}

fn bench_streaming() -> Result<(), VaultError> {
    eprintln!("--- Streaming Encryption ---");

    let key = SecureBuf::random(32)?;
    let data_sizes = [1024, 65_536, 1_048_576, 16_777_216]; // 1KB, 64KB, 1MB, 16MB

    for &size in &data_sizes {
        let data = vec![0x42u8; size];

        let start = Instant::now();
        let mut out = Vec::with_capacity(size + size / 64 * 41);
        stream::encrypt_stream(
            &mut data.as_slice(), &mut out, &key,
            aead::AeadAlgorithm::XChaCha20Poly1305, stream::DEFAULT_CHUNK_SIZE,
        )?;
        let elapsed = start.elapsed();

        let mb_per_sec = size as f64 / elapsed.as_secs_f64() / 1_048_576.0;
        let overhead = (out.len() as f64 / size as f64 - 1.0) * 100.0;
        eprintln!("  {:>8}: {:.0} MB/s ({:.1}% overhead, {:.2?})",
            format_size(size), mb_per_sec, overhead, elapsed);
    }

    eprintln!();
    Ok(())
}

fn bench_hashing() -> Result<(), VaultError> {
    eprintln!("--- Hashing ---");

    let data = vec![0x42u8; 16_777_216]; // 16 MB

    // BLAKE3
    let start = Instant::now();
    for _ in 0..10 {
        let _ = blake3::hash(&data);
    }
    let elapsed = start.elapsed();
    let mb_per_sec = (10.0 * data.len() as f64) / elapsed.as_secs_f64() / 1_048_576.0;
    eprintln!("  BLAKE3:   {:.0} MB/s (16MB blocks)", mb_per_sec);

    // SHA-256
    use sha2::Digest;
    let start = Instant::now();
    for _ in 0..10 {
        let mut h = sha2::Sha256::new();
        h.update(&data);
        let _ = h.finalize();
    }
    let elapsed = start.elapsed();
    let mb_per_sec = (10.0 * data.len() as f64) / elapsed.as_secs_f64() / 1_048_576.0;
    eprintln!("  SHA-256:  {:.0} MB/s (16MB blocks)", mb_per_sec);

    eprintln!();
    Ok(())
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{}MB", bytes / 1_048_576)
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}B", bytes)
    }
}
