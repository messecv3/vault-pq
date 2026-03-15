//! CPU feature detection for hardware-accelerated crypto.

/// Check if AES-NI is available on this CPU.
pub fn has_aes_ni() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        false
    }
}

/// Print detected hardware crypto capabilities.
pub fn print_capabilities() {
    eprintln!("Hardware crypto capabilities:");
    eprintln!("  AES-NI: {}", if has_aes_ni() { "yes" } else { "no" });

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        eprintln!("  SSE2:   {}", if std::arch::is_x86_feature_detected!("sse2") { "yes" } else { "no" });
        eprintln!("  AVX2:   {}", if std::arch::is_x86_feature_detected!("avx2") { "yes" } else { "no" });
    }
}
