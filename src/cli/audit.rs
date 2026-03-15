//! `vault audit` — inspect a vault file without decrypting.
//!
//! Shows: format version, stanza count/types, body entropy, file size,
//! chi-squared uniformity test. Useful for verifying encryption quality
//! and inspecting files you can't (or don't want to) decrypt.

use std::fs;
use std::path::PathBuf;
use crate::format::header;
use crate::platform::entropy;
use crate::error::VaultError;

pub fn run(input: PathBuf) -> Result<(), VaultError> {
    let data = fs::read(&input)
        .map_err(|_| VaultError::FileNotFound(input.display().to_string()))?;

    eprintln!("=== Vault File Audit ===");
    eprintln!("File:       {}", input.display());
    eprintln!("Size:       {} bytes", data.len());

    // Parse header
    let mut cursor = std::io::Cursor::new(&data);
    match header::read_stanzas(&mut cursor) {
        Ok((stanzas, magic)) => {
            eprintln!("Format:     VAULT v{}.{}", magic[6], magic[7]);
            eprintln!("Stanzas:    {}", stanzas.len());

            for (i, stanza) in stanzas.iter().enumerate() {
                match stanza {
                    header::RecipientStanza::Passphrase { params, .. } => {
                        eprintln!("  [{:>2}] Passphrase (Argon2id: {}MB, {} iter, {} threads)",
                            i,
                            params.memory_kib / 1024,
                            params.iterations,
                            params.parallelism,
                        );
                    }
                    header::RecipientStanza::PublicKey { encap_data, .. } => {
                        eprintln!("  [{:>2}] Public Key (X25519+ML-KEM-768, {} bytes encap)",
                            i, encap_data.len(),
                        );
                    }
                }
            }

            let header_end = cursor.position() as usize;
            // Metadata section: nonce(24) + len(4) + encrypted(variable)
            if header_end + 28 < data.len() {
                let meta_ct_len = u32::from_le_bytes(
                    data[header_end + 24..header_end + 28].try_into().unwrap_or([0; 4])
                ) as usize;
                let body_start = header_end + 28 + meta_ct_len;

                eprintln!("Header:     {} bytes", body_start);
                eprintln!("Body:       {} bytes", data.len() - body_start);

                // Entropy analysis of body
                if body_start < data.len() {
                    let body = &data[body_start..];
                    analyze_entropy(body);
                }
            }
        }
        Err(e) => {
            eprintln!("Parse error: {}", e);
            eprintln!("\nFalling back to raw entropy analysis...");
            analyze_entropy(&data);
        }
    }

    Ok(())
}

fn analyze_entropy(data: &[u8]) {
    eprintln!("\n--- Entropy Analysis ---");

    let overall = entropy::shannon_entropy(data);
    eprintln!("Overall:    {:.4} bits/byte — {}",
        overall, entropy::classify_entropy(overall));

    let chi2 = entropy::chi_squared(data);
    let chi2_quality = if chi2 < 300.0 { "excellent" }
        else if chi2 < 400.0 { "good" }
        else if chi2 < 600.0 { "acceptable" }
        else { "suspicious" };
    eprintln!("Chi-squared: {:.1} ({})", chi2, chi2_quality);

    // Section analysis
    let num_sections = if data.len() > 4096 { 8 } else { 4 };
    let sections = entropy::section_entropy(data, num_sections);
    eprintln!("\nPer-section entropy ({} sections):", num_sections);
    for (start, end, e) in &sections {
        let bar_len = ((e / 8.0) * 40.0) as usize;
        let bar: String = "█".repeat(bar_len) + &"░".repeat(40 - bar_len);
        eprintln!("  0x{:08x}-0x{:08x}: {:.4} {}", start, end, e, bar);
    }

    // Check for entropy anomalies
    let min_section = sections.iter().map(|s| s.2).fold(f64::INFINITY, f64::min);
    let max_section = sections.iter().map(|s| s.2).fold(f64::NEG_INFINITY, f64::max);
    let variance = max_section - min_section;

    if variance > 0.5 {
        eprintln!("\n  WARNING: Entropy variance {:.2} across sections.", variance);
        eprintln!("  Well-encrypted data should have uniform entropy.");
    }

    // Byte frequency histogram (top 5 most/least common)
    let freq = entropy::byte_distribution(data);
    let expected = data.len() as f64 / 256.0;
    let mut deviations: Vec<(u8, f64)> = (0..=255u8)
        .map(|b| (b, (freq[b as usize] as f64 - expected).abs() / expected))
        .collect();
    deviations.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    eprintln!("\nMost deviant bytes (from uniform):");
    for (byte, _dev) in deviations.iter().take(5) {
        eprintln!("  0x{:02x}: {} occurrences ({:+.1}% from expected)",
            byte, freq[*byte as usize],
            (freq[*byte as usize] as f64 / expected - 1.0) * 100.0
        );
    }
}
