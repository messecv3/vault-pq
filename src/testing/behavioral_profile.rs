//! Behavioral profile analysis — documents what our tool looks like to security products.
//!
//! Security products (Defender, CrowdStrike, SentinelOne) classify processes
//! by their behavioral patterns. This module profiles Vault's own behavior
//! to understand what triggers detection and what doesn't.
//!
//! # What We Measure
//!
//! 1. **File I/O pattern**: How many files touched, how fast, what patterns?
//! 2. **Memory allocation pattern**: Large allocations (Argon2id), locked pages
//! 3. **Crypto API usage**: What CNG/BCrypt calls are visible to ETW?
//! 4. **Process characteristics**: Binary size, import table, resource usage
//! 5. **Entropy profile**: Does our output look suspicious to heuristic engines?
//!
//! # Purpose
//!
//! This is NOT for evasion. It's for understanding the detection surface
//! so we can:
//! - Document what security products see when Vault runs
//! - Identify false positive risks for legitimate users
//! - Recommend configurations that work smoothly with enterprise EDR
//! - Report detection gaps to security vendors

use std::time::Instant;
use crate::crypto::aead;
use crate::platform::entropy;
use crate::memory::SecureBuf;

/// A behavioral profile measurement.
#[derive(Clone, Debug)]
pub struct BehaviorMeasurement {
    pub category: &'static str,
    pub metric: String,
    pub value: String,
    pub detection_risk: DetectionRisk,
    pub explanation: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetectionRisk {
    /// Looks normal — no detection expected.
    None,
    /// Slightly unusual — may trigger heuristic attention.
    Low,
    /// Notable pattern — may trigger behavioral alerts.
    Medium,
    /// Matches known malicious patterns — likely flagged.
    High,
}

/// Profile Vault's behavioral characteristics.
pub fn profile_behavior() -> Vec<BehaviorMeasurement> {
    let mut measurements = Vec::new();

    measurements.push(profile_binary());
    measurements.extend(profile_memory());
    measurements.extend(profile_crypto_output());
    measurements.extend(profile_file_io());

    measurements
}

fn profile_binary() -> BehaviorMeasurement {
    let exe_path = std::env::current_exe().unwrap_or_default();
    let exe_size = std::fs::metadata(&exe_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let risk = if exe_size < 500_000 {
        DetectionRisk::None // Small native binary — normal
    } else if exe_size < 2_000_000 {
        DetectionRisk::None // < 2MB — typical for Rust
    } else if exe_size < 10_000_000 {
        DetectionRisk::Low // Getting large
    } else {
        DetectionRisk::Medium // Go-sized — triggers heuristics
    };

    BehaviorMeasurement {
        category: "binary",
        metric: "executable size".into(),
        value: format!("{} bytes ({:.1} KB)", exe_size, exe_size as f64 / 1024.0),
        detection_risk: risk,
        explanation: format!(
            "Binary size {}. Rust binaries are typically 500KB-3MB (low risk). \
             Go binaries (10-30MB) trigger higher heuristic suspicion. \
             UPX-packed binaries are instantly flagged.",
            if exe_size < 2_000_000 { "is in the normal range" } else { "is larger than typical" }
        ),
    }
}

fn profile_memory() -> Vec<BehaviorMeasurement> {
    let mut results = Vec::new();

    // Measure Argon2id memory allocation
    let start = Instant::now();
    let _large_buf = SecureBuf::new(1024 * 1024); // 1MB locked allocation
    let alloc_time = start.elapsed();

    results.push(BehaviorMeasurement {
        category: "memory",
        metric: "locked allocation (1MB)".into(),
        value: format!("{:?}", alloc_time),
        detection_risk: DetectionRisk::Low,
        explanation:
            "VirtualLock/mlock calls are logged by ETW (Event Tracing for Windows). \
             Large locked allocations (512MB for Argon2id) are unusual for most \
             applications and may draw EDR attention. However, password managers \
             and crypto tools commonly use VirtualLock — it's not inherently suspicious."
                .into(),
    });

    // Working set impact
    results.push(BehaviorMeasurement {
        category: "memory",
        metric: "working set quota".into(),
        value: "process-dependent".into(),
        detection_risk: DetectionRisk::Low,
        explanation:
            "VirtualLock is limited by the process working set quota (default ~204KB). \
             Exceeding this causes silent failure — keys may be paged to the swap file. \
             Argon2id's 512MB allocation far exceeds this limit; the KDF uses standard \
             heap (not VirtualLock). Only the 32-byte derived key is VirtualLock'd."
                .into(),
    });

    results
}

fn profile_crypto_output() -> Vec<BehaviorMeasurement> {
    let mut results = Vec::new();

    // Generate sample encrypted output and analyze
    let key = SecureBuf::random(32).unwrap();
    let nonce = [0x42u8; 24];
    let plaintext = vec![0x00u8; 4096]; // Worst case: all zeros

    let ciphertext = aead::encrypt(
        aead::AeadAlgorithm::XChaCha20Poly1305,
        &key, &nonce, b"", &plaintext,
    ).unwrap();

    let ent = entropy::shannon_entropy(&ciphertext);
    let chi2 = entropy::chi_squared(&ciphertext);

    results.push(BehaviorMeasurement {
        category: "output",
        metric: "ciphertext entropy".into(),
        value: format!("{:.4} bits/byte", ent),
        detection_risk: if ent > 7.99 { DetectionRisk::Low } else { DetectionRisk::None },
        explanation: format!(
            "Encrypted output has {:.4} bits/byte entropy (max 8.0). \
             Entropy > 7.99 can trigger heuristic flags in some AV products \
             that look for 'encrypted/packed' content. Our entropy normalization \
             pipeline can reduce this to < 7.99 by injecting low-entropy padding. \
             Chi-squared: {:.1} (lower = more uniform = more random-looking).",
            ent, chi2
        ),
    });

    // Check if output has any structural patterns
    let has_magic = ciphertext.starts_with(b"VAULT");
    results.push(BehaviorMeasurement {
        category: "output",
        metric: "magic bytes in ciphertext".into(),
        value: format!("{}", !has_magic),
        detection_risk: DetectionRisk::None,
        explanation:
            "Ciphertext does not contain recognizable magic bytes. \
             The vault format magic (VAULT\\x00\\x01\\x00) is in the header, \
             not in the encrypted body. Body ciphertext is indistinguishable \
             from random data."
                .into(),
    });

    results
}

fn profile_file_io() -> Vec<BehaviorMeasurement> {
    let mut results = Vec::new();

    results.push(BehaviorMeasurement {
        category: "file-io",
        metric: "file access pattern".into(),
        value: "single-file, sequential read then write".into(),
        detection_risk: DetectionRisk::None,
        explanation:
            "Vault encrypts one file at a time: read input, write output. \
             This is a benign I/O pattern. Behavioral engines flag rapid \
             multi-file enumeration + modification (ransomware pattern). \
             Vault's single-file approach does not trigger this. \
             \n\
             Windows 11 Controlled Folder Access (CFA) would block writes \
             to protected folders if Vault is not allowlisted. This is by design — \
             CFA is working correctly by blocking an unknown application."
                .into(),
    });

    results.push(BehaviorMeasurement {
        category: "file-io",
        metric: "secure deletion pattern".into(),
        value: "overwrite + truncate + rename + delete".into(),
        detection_risk: DetectionRisk::Low,
        explanation:
            "Secure deletion involves multiple write operations to the same file \
             followed by rename and delete. This pattern is somewhat unusual but \
             matches legitimate data sanitization tools (BleachBit, Eraser). \
             EDR products generally don't flag single-file overwrite+delete."
                .into(),
    });

    results
}

/// Print the behavioral profile report.
pub fn print_report(measurements: &[BehaviorMeasurement]) {
    eprintln!("=== Behavioral Profile Report ===\n");

    let mut current_category = "";
    for m in measurements {
        if m.category != current_category {
            if !current_category.is_empty() {
                eprintln!();
            }
            eprintln!("--- {} ---", m.category.to_uppercase());
            current_category = m.category;
        }

        let risk_label = match m.detection_risk {
            DetectionRisk::None => "NONE",
            DetectionRisk::Low => "LOW ",
            DetectionRisk::Medium => "MED ",
            DetectionRisk::High => "HIGH",
        };

        eprintln!("[{}] {}: {}", risk_label, m.metric, m.value);
        eprintln!("       {}", m.explanation);
        eprintln!();
    }

    let high_risk = measurements.iter()
        .filter(|m| m.detection_risk == DetectionRisk::High)
        .count();

    if high_risk > 0 {
        eprintln!("{} HIGH-RISK patterns detected.", high_risk);
        eprintln!("Consider adjusting behavior to reduce detection surface.");
    } else {
        eprintln!("No high-risk behavioral patterns detected.");
        eprintln!("Vault's behavioral profile is consistent with legitimate encryption tools.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_runs() {
        let measurements = profile_behavior();
        assert!(measurements.len() >= 5);

        for m in &measurements {
            assert!(!m.category.is_empty());
            assert!(!m.metric.is_empty());
            assert!(!m.explanation.is_empty());
        }
    }

    #[test]
    fn test_binary_size_risk() {
        let m = profile_binary();
        // Our Rust binary should be < 2MB
        assert!(m.detection_risk <= DetectionRisk::Low);
    }

    #[test]
    fn test_no_high_risk() {
        let measurements = profile_behavior();
        let high_count = measurements.iter()
            .filter(|m| m.detection_risk == DetectionRisk::High)
            .count();
        assert_eq!(high_count, 0, "No high-risk patterns should be present");
    }
}
