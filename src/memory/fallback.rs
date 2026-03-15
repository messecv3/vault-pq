//! Fallback secure memory for platforms without mlock/VirtualLock.
//! Uses standard allocation with Zeroize — no locking guarantees.

#![allow(dead_code)] // Only used on non-Windows/Unix platforms

use crate::error::VaultError;
use crate::memory::SecureBuf;

pub fn secure_alloc(len: usize) -> Result<SecureBuf, VaultError> {
    let layout = std::alloc::Layout::from_size_align(len, 8)
        .map_err(|_| VaultError::SecureAllocFailed("invalid layout".into()))?;

    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return Err(VaultError::SecureAllocFailed("allocation failed".into()));
    }

    Ok(SecureBuf {
        ptr,
        len,
        alloc_size: len,
        locked: false,
    })
}

pub fn secure_free(ptr: *mut u8, alloc_size: usize) {
    let layout = std::alloc::Layout::from_size_align(alloc_size, 8).unwrap();
    unsafe { std::alloc::dealloc(ptr, layout) };
}
