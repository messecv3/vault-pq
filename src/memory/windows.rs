//! Windows secure memory implementation using VirtualAlloc + VirtualLock + guard pages.

use crate::error::VaultError;
use crate::memory::SecureBuf;

use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE,
};

/// System page size (cached).
fn page_size() -> usize {
    // Windows guarantees at least 4096
    4096
}

pub fn secure_alloc(len: usize) -> Result<SecureBuf, VaultError> {
    let ps = page_size();

    // Calculate: guard_page | usable_pages... | guard_page
    let usable_pages = (len + ps - 1) / ps;
    let total_size = (usable_pages + 2) * ps;

    unsafe {
        // Reserve + commit the entire region
        let base = VirtualAlloc(
            std::ptr::null(),
            total_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );
        if base.is_null() {
            return Err(VaultError::SecureAllocFailed(
                "VirtualAlloc failed".into(),
            ));
        }

        // First page: guard (PAGE_NOACCESS)
        let mut old_protect = 0u32;
        VirtualProtect(base, ps, PAGE_NOACCESS, &mut old_protect);

        // Last page: guard (PAGE_NOACCESS)
        let last_page = (base as *mut u8).add(total_size - ps);
        VirtualProtect(last_page as *const _, ps, PAGE_NOACCESS, &mut old_protect);

        // Usable region is between the guards
        let usable_ptr = (base as *mut u8).add(ps);
        let usable_size = usable_pages * ps;

        // Zero the usable region
        std::ptr::write_bytes(usable_ptr, 0, usable_size);

        // Lock into physical RAM — prevents swapping to pagefile.
        // This can fail if the process working set limit is too low.
        let locked = VirtualLock(usable_ptr as *const _, usable_size) != 0;
        if !locked {
            // Non-fatal: we still have the allocation, just not locked.
            // This happens on low-privilege processes or when working set quota is exhausted.
            eprintln!("warning: VirtualLock failed — memory may be swapped to disk");
        }

        Ok(SecureBuf {
            ptr: usable_ptr,
            len,
            alloc_size: total_size,
            locked,
        })
    }
}

pub fn secure_free(ptr: *mut u8, alloc_size: usize, locked: bool) {
    let ps = page_size();

    unsafe {
        if locked {
            let usable_size = alloc_size - 2 * ps;
            VirtualUnlock(ptr as *const _, usable_size);
        }

        // Free the entire allocation (base = ptr - guard page)
        let base = ptr.sub(ps);
        VirtualFree(base as *mut _, 0, MEM_RELEASE);
    }
}
