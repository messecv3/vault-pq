//! Secure memory management.
//!
//! Provides `SecureBuf` — a buffer that is:
//! - Locked into physical RAM (not swapped to disk)
//! - Protected by guard pages (overflow = segfault, not leak)
//! - Zeroed on drop (guaranteed, compiler-fence-backed)
//! - Excluded from core dumps (Unix)
//!
//! NEVER implements Clone, Debug, Display, or Serialize.

#[cfg(windows)]
mod windows;
#[cfg(unix)]
mod unix;
mod fallback;

use std::sync::atomic::{fence, Ordering};
use crate::error::VaultError;

/// A secure buffer for cryptographic secrets.
///
/// Memory is locked into RAM, bounded by guard pages, and zeroed on drop.
/// This type intentionally does NOT implement Clone, Debug, Display, or
/// any serialization trait — secrets must not be copied, printed, or transmitted.
pub struct SecureBuf {
    ptr: *mut u8,
    len: usize,
    /// Total allocation size including guard pages.
    alloc_size: usize,
    /// Whether platform-level locking succeeded.
    locked: bool,
}

// SecureBuf is Send (can move between threads) but not Sync (no shared references).
// The buffer is exclusively owned.
unsafe impl Send for SecureBuf {}

impl SecureBuf {
    /// Allocate a new secure buffer of exactly `len` bytes, zeroed.
    pub fn new(len: usize) -> Result<Self, VaultError> {
        if len == 0 {
            return Err(VaultError::SecureAllocFailed("zero-length buffer".into()));
        }
        platform_alloc(len)
    }

    /// Allocate and fill with cryptographically random bytes.
    pub fn random(len: usize) -> Result<Self, VaultError> {
        let mut buf = Self::new(len)?;
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buf.expose_mut());
        Ok(buf)
    }

    /// Allocate and copy from an existing slice. The source is NOT zeroed.
    pub fn from_slice(data: &[u8]) -> Result<Self, VaultError> {
        let mut buf = Self::new(data.len())?;
        buf.expose_mut().copy_from_slice(data);
        Ok(buf)
    }

    /// Number of bytes in the buffer.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Expose the buffer contents for reading.
    pub fn expose(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Expose the buffer contents for writing.
    pub fn expose_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for SecureBuf {
    fn drop(&mut self) {
        // Zero all bytes using volatile writes (cannot be optimized away)
        unsafe {
            for i in 0..self.len {
                std::ptr::write_volatile(self.ptr.add(i), 0u8);
            }
        }
        // Compiler fence ensures zeroing completes before deallocation
        fence(Ordering::SeqCst);

        // Platform-specific deallocation
        platform_free(self.ptr, self.alloc_size, self.locked);
    }
}

// Intentionally NOT implementing:
// - Clone: secrets must not be duplicated
// - Debug/Display: secrets must not be printed
// - Serialize: secrets must not be transmitted
// - PartialEq: comparison must be constant-time (use separate function)

/// Constant-time comparison of two byte slices.
/// Returns true if equal, false otherwise. Timing does not depend on content.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// Platform dispatch
#[cfg(windows)]
fn platform_alloc(len: usize) -> Result<SecureBuf, VaultError> {
    windows::secure_alloc(len)
}

#[cfg(unix)]
fn platform_alloc(len: usize) -> Result<SecureBuf, VaultError> {
    unix::secure_alloc(len)
}

#[cfg(not(any(windows, unix)))]
fn platform_alloc(len: usize) -> Result<SecureBuf, VaultError> {
    fallback::secure_alloc(len)
}

#[cfg(windows)]
fn platform_free(ptr: *mut u8, alloc_size: usize, locked: bool) {
    windows::secure_free(ptr, alloc_size, locked);
}

#[cfg(unix)]
fn platform_free(ptr: *mut u8, alloc_size: usize, locked: bool) {
    unix::secure_free(ptr, alloc_size, locked);
}

#[cfg(not(any(windows, unix)))]
fn platform_free(ptr: *mut u8, alloc_size: usize, _locked: bool) {
    fallback::secure_free(ptr, alloc_size);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_and_zero() {
        let buf = SecureBuf::new(64).expect("alloc failed");
        assert_eq!(buf.len(), 64);
        // Initially zeroed
        assert!(buf.expose().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_fill() {
        let buf = SecureBuf::random(32).expect("alloc failed");
        // Extremely unlikely all 32 bytes are zero
        assert!(!buf.expose().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_from_slice() {
        let data = b"secret key material here!!!!!!!";
        let buf = SecureBuf::from_slice(data).expect("alloc failed");
        assert_eq!(buf.expose(), data);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello worle";
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, &a[..5])); // different lengths
    }
}
