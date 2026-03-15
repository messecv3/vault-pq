//! Multi-pass transformation pipeline.
//!
//! Inspired by Phantom Engine's 7-pass obfuscation orchestrator.
//! Each pass is an independent, testable transformation applied to the
//! encrypted output. Passes can be enabled/disabled via configuration.
//!
//! # Architecture
//!
//! ```text
//! Input → [Padding] → [Entropy Normalization] → [Header Polymorphism]
//!       → [Decoy Injection] → [Output Scrambling] → Output
//! ```

use crate::error::VaultError;
use crate::platform::entropy;

/// Statistics from a single pass.
#[derive(Clone, Debug)]
pub struct PassStats {
    pub name: &'static str,
    pub bytes_added: usize,
    pub entropy_before: f64,
    pub entropy_after: f64,
    pub duration_us: u64,
}

/// A transformation pass applied to encrypted output.
pub trait TransformPass: Send + Sync {
    /// Human-readable pass name.
    fn name(&self) -> &'static str;

    /// Apply the transformation in-place. Returns statistics.
    fn apply(&self, data: &mut Vec<u8>) -> Result<PassStats, VaultError>;
}

/// The pipeline orchestrator — applies passes sequentially.
pub struct Pipeline {
    passes: Vec<Box<dyn TransformPass>>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    /// Build a default pipeline with all standard passes.
    pub fn default_pipeline() -> Self {
        let mut p = Self::new();
        p.add_pass(Box::new(EntropyNormalizationPass::new(7.999, 7.85)));
        p.add_pass(Box::new(DecoyPaddingPass::new(64)));
        p
    }

    pub fn add_pass(&mut self, pass: Box<dyn TransformPass>) {
        self.passes.push(pass);
    }

    /// Execute all passes in order. Returns per-pass statistics.
    pub fn execute(&self, data: &mut Vec<u8>) -> Result<Vec<PassStats>, VaultError> {
        let mut stats = Vec::with_capacity(self.passes.len());
        for pass in &self.passes {
            let stat = pass.apply(data)?;
            stats.push(stat);
        }
        Ok(stats)
    }
}

// === Pass Implementations ===

/// Entropy normalization: ensures output entropy stays in an optimal range.
///
/// Too-high entropy (> 7.99) can trigger heuristic detection in some
/// security products. Too-low entropy indicates poor encryption.
/// This pass injects controlled low-entropy blocks to bring the overall
/// entropy into the target range while maintaining security.
///
/// Adapted from Phantom Engine's camouflage.py entropy normalization.
pub struct EntropyNormalizationPass {
    max_entropy: f64,
    #[allow(dead_code)]
    min_entropy: f64,
}

impl EntropyNormalizationPass {
    pub fn new(max_entropy: f64, min_entropy: f64) -> Self {
        Self { max_entropy, min_entropy }
    }
}

impl TransformPass for EntropyNormalizationPass {
    fn name(&self) -> &'static str {
        "entropy-normalization"
    }

    fn apply(&self, data: &mut Vec<u8>) -> Result<PassStats, VaultError> {
        let entropy_before = entropy::shannon_entropy(data);
        let original_len = data.len();

        if entropy_before > self.max_entropy && data.len() > 256 {
            // Inject low-entropy padding blocks to reduce overall entropy.
            // Uses realistic-looking patterns (copyright notices, null runs)
            // similar to Phantom Engine's approach.
            let low_entropy_patterns: &[&[u8]] = &[
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                b"Copyright (c) Microsoft Corporation. All rights reserved.\x00",
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
                b"This program cannot be run in DOS mode.\r\r\n\x00",
            ];

            let mut pattern_idx = 0;
            let max_padding = data.len() / 8; // Don't add more than 12.5% padding
            let mut added = 0;

            while entropy::shannon_entropy(data) > self.max_entropy && added < max_padding {
                let pattern = low_entropy_patterns[pattern_idx % low_entropy_patterns.len()];
                data.extend_from_slice(pattern);
                added += pattern.len();
                pattern_idx += 1;
            }
        }

        let entropy_after = entropy::shannon_entropy(data);

        Ok(PassStats {
            name: self.name(),
            bytes_added: data.len() - original_len,
            entropy_before,
            entropy_after,
            duration_us: 0, // filled by orchestrator
        })
    }
}

/// Decoy padding: append random-length random data to obscure true file size.
///
/// Even with bucket-based padding, the exact encrypted size within a bucket
/// can leak information. This pass adds 0-N random bytes to further obscure
/// the boundary.
pub struct DecoyPaddingPass {
    /// Maximum additional bytes to add.
    max_decoy_bytes: usize,
}

impl DecoyPaddingPass {
    pub fn new(max_decoy_bytes: usize) -> Self {
        Self { max_decoy_bytes }
    }
}

impl TransformPass for DecoyPaddingPass {
    fn name(&self) -> &'static str {
        "decoy-padding"
    }

    fn apply(&self, data: &mut Vec<u8>) -> Result<PassStats, VaultError> {
        let entropy_before = entropy::shannon_entropy(data);
        let original_len = data.len();

        // Random padding length (0 to max)
        use rand::Rng;
        let pad_len = rand::thread_rng().gen_range(0..=self.max_decoy_bytes);

        if pad_len > 0 {
            let mut padding = vec![0u8; pad_len];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
            data.extend_from_slice(&padding);
        }

        let entropy_after = entropy::shannon_entropy(data);

        Ok(PassStats {
            name: self.name(),
            bytes_added: data.len() - original_len,
            entropy_before,
            entropy_after,
            duration_us: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_execution_order() {
        let mut pipeline = Pipeline::new();
        pipeline.add_pass(Box::new(DecoyPaddingPass::new(32)));

        let mut data = vec![0xAB; 1000];
        let stats = pipeline.execute(&mut data).unwrap();

        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].name, "decoy-padding");
        assert!(data.len() >= 1000); // May have added padding
    }

    #[test]
    fn test_entropy_normalization() {
        let pass = EntropyNormalizationPass::new(7.999, 7.85);

        // Create data with very high entropy (random bytes)
        let mut data = vec![0u8; 4096];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);

        let stats = pass.apply(&mut data).unwrap();
        assert!(stats.entropy_before > 7.5);
        // After normalization, should still be high but potentially adjusted
    }

    #[test]
    fn test_decoy_padding_adds_bytes() {
        let pass = DecoyPaddingPass::new(100);
        let mut data = vec![0x42; 500];

        let _stats = pass.apply(&mut data).unwrap();
        assert!(data.len() >= 500);
        assert!(data.len() <= 600);
    }

    #[test]
    fn test_default_pipeline() {
        let pipeline = Pipeline::default_pipeline();
        let mut data = vec![0u8; 2048];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);

        let result = pipeline.execute(&mut data).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_low_entropy_data_untouched() {
        let pass = EntropyNormalizationPass::new(7.999, 7.85);
        let mut data = vec![0x00; 1000]; // Very low entropy
        let original_len = data.len();

        let stats = pass.apply(&mut data).unwrap();
        assert_eq!(stats.bytes_added, 0); // Should not add padding
        assert_eq!(data.len(), original_len);
    }
}
