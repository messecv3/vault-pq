# Security Policy

## Reporting Vulnerabilities

If you find a security vulnerability in Vault, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email the details to the maintainer privately.
3. Include steps to reproduce, affected versions, and potential impact.
4. Allow reasonable time for a fix before public disclosure.

## Scope

The following are in scope:
- Cryptographic implementation flaws
- Key material leakage (memory, disk, logs)
- Authentication bypass
- Header format parsing vulnerabilities
- License signature bypass

## Known Limitations

These are documented and not considered vulnerabilities:

- Stack frames not zeroed in release builds (Rust compiler limitation)
- VirtualLock working set limit (~204KB) exceeded by Argon2id
- NTFS $MFT retaining filename history after secure deletion
- Guard pages making SecureBuf allocations identifiable in memory dumps
- Compression before encryption can leak information through size changes (mitigated by bucket padding)
