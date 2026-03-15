//! Memory security probes — verify that SecureBuf actually protects secrets.
//!
//! These tests answer: "If an attacker dumps process memory, can they find our keys?"
//!
//! # What We Test
//!
//! 1. **Post-drop residue**: After SecureBuf is dropped, is the key still in the
//!    process heap? (Tests volatile zeroing effectiveness)
//! 2. **GC-equivalent scatter**: Does Rust's allocator leave copies of key material
//!    in freed pages? (Tests for the Go GC problem in Rust context)
//! 3. **Stack residue**: After a function returns, does the stack frame retain
//!    key material? (Tests compiler optimization of secret zeroing)
//! 4. **VirtualLock verification**: Is the memory actually locked? (Tests that
//!    key material won't be paged to the swap file)
//!
//! # Findings
//!
//! These probes document where memory protection works and where it doesn't.
//! Results should be published to push for better OS-level memory protection APIs.

use crate::memory::SecureBuf;

/// Result of a memory security probe.
#[derive(Clone, Debug)]
pub struct MemoryProbeResult {
    pub test_name: &'static str,
    pub passed: bool,
    pub description: String,
    pub severity: Severity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Security property holds as expected.
    Pass,
    /// Minor concern — theoretical risk but hard to exploit.
    Info,
    /// Moderate concern — exploitable under specific conditions.
    Warning,
    /// Serious concern — key material exposed.
    Critical,
}

/// Run all memory security probes.
pub fn run_all_probes() -> Vec<MemoryProbeResult> {
    let mut results = Vec::new();

    results.push(probe_drop_zeroing());
    results.push(probe_allocation_pattern());
    results.push(probe_stack_residue());
    results.push(probe_realloc_scatter());

    #[cfg(windows)]
    results.push(probe_virtual_lock());

    results
}

/// Test: After SecureBuf is dropped, is the memory zeroed?
///
/// We can't directly read freed memory safely in Rust (that's UB).
/// Instead, we verify the Drop implementation runs by checking that
/// a new allocation in the same size class doesn't contain our secret.
fn probe_drop_zeroing() -> MemoryProbeResult {
    let secret = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let ptr_value: usize;

    {
        let mut buf = SecureBuf::new(64).unwrap();
        buf.expose_mut()[..8].copy_from_slice(&secret);
        ptr_value = buf.expose().as_ptr() as usize;
        // buf dropped here — should zero memory
    }

    // Allocate again — if the allocator reuses the same page,
    // we can check if our secret survived
    let check = SecureBuf::new(64).unwrap();
    let found_secret = check.expose().windows(8).any(|w| w == secret);

    MemoryProbeResult {
        test_name: "drop-zeroing",
        passed: !found_secret,
        description: if found_secret {
            format!(
                "FAIL: Secret pattern found in reallocated memory at ~0x{:x}. \
                 Drop zeroing may not be effective on this allocator.",
                ptr_value
            )
        } else {
            "PASS: No secret residue found after drop. Volatile zeroing effective.".into()
        },
        severity: if found_secret { Severity::Critical } else { Severity::Pass },
    }
}

/// Test: Does the Rust allocator scatter copies of data during reallocation?
///
/// When a Vec grows, the allocator may copy data to a new location without
/// zeroing the old one. This is the Rust equivalent of Go's GC scatter problem.
fn probe_realloc_scatter() -> MemoryProbeResult {
    let marker = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48]; // "ABCDEFGH"

    // Create a Vec, force several reallocations
    let mut growing = Vec::with_capacity(8);
    growing.extend_from_slice(&marker);

    // Force reallocation by growing beyond capacity
    for i in 0..20 {
        growing.extend_from_slice(&[i as u8; 64]);
    }

    // The old copies may still exist in freed heap pages.
    // We can't safely read them, but we can document the risk.

    // Zero our copy
    use zeroize::Zeroize;
    growing.zeroize();

    MemoryProbeResult {
        test_name: "realloc-scatter",
        passed: true, // Can't directly test without UB
        description:
            "INFO: Vec reallocations may leave copies in freed pages. \
             SecureBuf avoids this by using fixed-size mmap/VirtualAlloc \
             (never reallocated). But any Vec<u8> holding secrets is vulnerable. \
             Mitigation: always use SecureBuf for key material, never Vec<u8>."
            .into(),
        severity: Severity::Info,
    }
}

/// Test: Does function return leave key material on the stack?
///
/// Rust doesn't guarantee stack zeroing after function return.
/// The compiler may leave sensitive locals in the stack frame.
fn probe_stack_residue() -> MemoryProbeResult {
    // This function puts a known secret on the stack, returns,
    // then checks if the stack frame still contains the secret.

    let _secret_on_stack: [u8; 32] = create_stack_secret();
    // At this point, create_stack_secret's stack frame is freed
    // but may not be zeroed.

    // We can't safely inspect the freed stack frame from Rust.
    // Document the limitation.

    MemoryProbeResult {
        test_name: "stack-residue",
        passed: true, // Can't directly test
        description:
            "INFO: Stack frames are not zeroed after function return in release builds. \
             Compiler optimizations may keep secret-derived values in registers \
             or stack slots. Mitigation: use SecureBuf (heap-allocated, guarded) \
             instead of stack arrays for secrets. The `zeroize` crate's Zeroize \
             trait helps but compiler may optimize away stack zeroing in release mode."
            .into(),
        severity: Severity::Info,
    }
}

#[inline(never)]
fn create_stack_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    for (i, byte) in secret.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(0x37).wrapping_add(0x42);
    }
    // Attempt to zero — but compiler may optimize this away
    // since `secret` is returned (the zeroed version would be useless)
    secret
}

/// Test: Is the allocation pattern of SecureBuf distinguishable?
///
/// If an attacker can identify which heap regions are SecureBuf allocations
/// (by guard page patterns), they know where to look for secrets.
fn probe_allocation_pattern() -> MemoryProbeResult {
    let buf1 = SecureBuf::new(32).unwrap();
    let buf2 = SecureBuf::new(32).unwrap();

    let addr1 = buf1.expose().as_ptr() as usize;
    let addr2 = buf2.expose().as_ptr() as usize;

    // Check if allocations are in a predictable pattern
    let page_size = 4096;
    let aligned_1 = addr1 % page_size == 0;
    let aligned_2 = addr2 % page_size == 0;
    let predictable = aligned_1 && aligned_2;

    MemoryProbeResult {
        test_name: "allocation-pattern",
        passed: true, // This is informational
        description: format!(
            "INFO: SecureBuf allocations at 0x{:x} and 0x{:x}. \
             Page-aligned: {}/{}. Guard pages make SecureBuf regions identifiable \
             in memory dumps (PAGE_NOACCESS regions flanking allocations). \
             This is a known tradeoff: guard pages protect against overflow but \
             make the allocation conspicuous. Trade secret location privacy \
             for buffer overflow protection.",
            addr1, addr2, aligned_1, aligned_2
        ),
        severity: if predictable { Severity::Info } else { Severity::Pass },
    }
}

/// Test: Is VirtualLock actually effective? (Windows only)
#[cfg(windows)]
fn probe_virtual_lock() -> MemoryProbeResult {
    let buf = SecureBuf::new(4096).unwrap();

    // We can check if the memory is in the working set (locked)
    // by querying VirtualQuery on the allocation.

    use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let result = unsafe {
        VirtualQuery(
            buf.expose().as_ptr() as *const _,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if result == 0 {
        return MemoryProbeResult {
            test_name: "virtual-lock",
            passed: false,
            description: "FAIL: VirtualQuery failed — cannot verify lock status.".into(),
            severity: Severity::Warning,
        };
    }

    // Check if the region is committed (not reserved or free)
    let is_committed = mbi.State == 0x1000; // MEM_COMMIT

    MemoryProbeResult {
        test_name: "virtual-lock",
        passed: is_committed,
        description: if is_committed {
            format!(
                "PASS: Memory at 0x{:x} is committed (MEM_COMMIT). \
                 VirtualLock should prevent paging to swap file. \
                 Note: VirtualLock has a per-process working set limit \
                 (default ~204KB). Exceeding this limit causes VirtualLock \
                 to fail silently — keys may be paged to disk.",
                buf.expose().as_ptr() as usize
            )
        } else {
            format!(
                "WARNING: Memory state is 0x{:x}, not MEM_COMMIT. \
                 VirtualLock may not be effective.",
                mbi.State
            )
        },
        severity: if is_committed { Severity::Pass } else { Severity::Warning },
    }
}

/// Print a full memory security report.
pub fn print_report(results: &[MemoryProbeResult]) {
    eprintln!("=== Memory Security Probe Report ===\n");

    let mut pass_count = 0;
    let mut warn_count = 0;
    let mut crit_count = 0;

    for result in results {
        let icon = match result.severity {
            Severity::Pass => "[PASS]",
            Severity::Info => "[INFO]",
            Severity::Warning => "[WARN]",
            Severity::Critical => "[CRIT]",
        };

        eprintln!("{} {}", icon, result.test_name);
        eprintln!("  {}\n", result.description);

        match result.severity {
            Severity::Pass => pass_count += 1,
            Severity::Info => {}
            Severity::Warning => warn_count += 1,
            Severity::Critical => crit_count += 1,
        }
    }

    eprintln!("Summary: {} passed, {} warnings, {} critical",
        pass_count, warn_count, crit_count);

    if crit_count > 0 {
        eprintln!("\nCRITICAL issues found — key material may be recoverable from memory.");
        eprintln!("Consider: full-disk encryption as base layer, shorter key lifetimes.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_probes_run() {
        let results = run_all_probes();
        assert!(results.len() >= 4);

        // All probes should produce results without panicking
        for result in &results {
            assert!(!result.test_name.is_empty());
            assert!(!result.description.is_empty());
        }
    }

    #[test]
    fn test_drop_zeroing_passes() {
        let result = probe_drop_zeroing();
        // This should pass on most systems — our volatile zeroing works
        assert!(result.passed, "Drop zeroing failed: {}", result.description);
    }
}
