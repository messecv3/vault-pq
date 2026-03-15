//! Unix secure memory implementation using mmap + mlock + guard pages.

use crate::error::VaultError;
use crate::memory::SecureBuf;

pub fn secure_alloc(len: usize) -> Result<SecureBuf, VaultError> {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

    let usable_pages = (len + ps - 1) / ps;
    let total_size = (usable_pages + 2) * ps;

    unsafe {
        // Allocate anonymous private mapping
        let base = libc::mmap(
            std::ptr::null_mut(),
            total_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        );
        if base == libc::MAP_FAILED {
            return Err(VaultError::SecureAllocFailed("mmap failed".into()));
        }

        // Guard pages: no access
        libc::mprotect(base, ps, libc::PROT_NONE);
        libc::mprotect(
            (base as *mut u8).add(total_size - ps) as *mut _,
            ps,
            libc::PROT_NONE,
        );

        let usable_ptr = (base as *mut u8).add(ps);
        let usable_size = usable_pages * ps;

        // Zero
        std::ptr::write_bytes(usable_ptr, 0, usable_size);

        // Lock into RAM
        let locked = libc::mlock(usable_ptr as *const _, usable_size) == 0;
        if !locked {
            eprintln!("warning: mlock failed — memory may be swapped to disk");
        }

        // Exclude from core dumps
        #[cfg(target_os = "linux")]
        {
            libc::madvise(usable_ptr as *mut _, usable_size, libc::MADV_DONTDUMP);
            libc::madvise(usable_ptr as *mut _, usable_size, libc::MADV_DONTFORK);
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
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

    unsafe {
        let usable_size = alloc_size - 2 * ps;

        if locked {
            libc::munlock(ptr as *const _, usable_size);
        }

        let base = ptr.sub(ps);
        libc::munmap(base as *mut _, alloc_size);
    }
}
