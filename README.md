# Vault

Post-quantum hybrid file encryption toolkit built in Rust.

Vault combines classical and post-quantum cryptography into a single tool — X25519 + ML-KEM-768 key exchange, XChaCha20-Poly1305 / AES-256-GCM authenticated encryption, Argon2id key derivation, Ed25519 signatures, and BLAKE3 hashing. Every cryptographic primitive is verified on startup via FIPS-style known-answer self-tests.

```
$ vault info
Hardware crypto capabilities:
  AES-NI: yes
  SSE2:   yes
  AVX2:   yes
Self-tests: passed
Machine ID: a1b2c3d4e5f6a7b8
License:    Development mode
```

---

## Features

### Core Encryption
- **Hybrid post-quantum key exchange** — X25519 + ML-KEM-768 (FIPS 203). If either algorithm is broken, the other still protects your data.
- **Dual AEAD** — XChaCha20-Poly1305 (software, 192-bit nonce) or AES-256-GCM (hardware-accelerated via AES-NI). Auto-selected based on CPU capabilities.
- **Argon2id KDF** — memory-hard key derivation with enforced minimums (64MB+). Resists GPU/ASIC brute-force attacks.
- **Streaming chunked encryption** — 64KB chunks with per-chunk HKDF-derived nonces. Encrypts files of any size without loading them into memory.
- **Multi-recipient** — encrypt once, multiple recipients can decrypt independently (passphrase and/or public key).
- **Zstd compression** — optional compression before encryption for significant size savings on text and documents.

### Metadata Protection
- **Content padding** — output padded to fixed bucket sizes (1KB → 4GB). File size is hidden.
- **Filename encryption** — output files named with random UUIDs. Original filename encrypted inside the header.
- **Timestamp normalization** — all output timestamps set to epoch. Prevents timeline analysis.

### Advanced Features
- **Encrypted file search** — BLAKE3 keyed-hash token index. Search across encrypted files by keyword without decrypting any of them.
- **Key rotation without re-encryption** — change who can access a file by replacing header stanzas. O(stanzas) not O(file_size). Instant re-keying on multi-gigabyte files.
- **Deniable encryption** — multiple passphrases decrypt to different content. Mathematically impossible to prove how many decryption paths exist.
- **Honeypot files** — generate vault files with invisible zero-width Unicode fingerprints. Identify which credential was compromised by examining the decrypted content.
- **Dead-man switch** — Ed25519-signed canary records with check-in deadlines. Verifiable without the encryption key.
- **Encrypted audit log** — BLAKE3 hash-chained, append-only, tamper-evident. Each entry independently encrypted. Chain verifiable without decryption.
- **Shamir secret sharing** — split keys into N shares, any K can reconstruct. Distribute trust across multiple parties.
- **ASCII armor** — PEM-style base64 output for pasting in email or chat.
- **Ed25519 signatures** — sign files with content-binding BLAKE3 hash.

### Security Analysis
- **FIPS-style self-tests** — known-answer validation of XChaCha20-Poly1305, AES-256-GCM, HKDF-SHA256, and BLAKE3 on every startup. Binary refuses to operate if any test fails.
- **Shannon entropy analysis** — per-section entropy, chi-squared uniformity, byte distribution deviation. Audit any file's encryption quality.
- **Memory security probes** — verify that VirtualLock works, drop zeroing is effective, no key residue in freed memory.
- **Forensic artifact probes** — test what NTFS leaves behind after secure deletion (content, filenames, timestamps, ADS).
- **Behavioral profiling** — document what the tool looks like to EDR/AV products. Binary size, I/O patterns, entropy profile.
- **Environment risk scoring** — weighted detection of unsafe runtime conditions (RDP, screen recording, debuggers).

### Secure Memory
- **Guard pages** — PAGE_NOACCESS before and after every secret buffer. Overflow = segfault, not leak.
- **VirtualLock / mlock** — key material pinned to physical RAM. Not paged to swap file.
- **Volatile zeroing** — compiler-fence-backed zeroing on drop. Cannot be optimized away.
- **No Clone/Debug/Display** — `SecureBuf` cannot be copied, printed, or serialized. Secrets don't leak through standard traits.

### Forensic Tooling
- **Secure deletion** — overwrite → truncate → rename → delete. Pollutes NTFS journal with random filename.
- **Multi-pass shred** — Quick (1-pass), DoD 5220.22-M (3-pass), Enhanced (7-pass).
- **Path whitelist** — regex/glob/env-var rules controlling which paths the tool can read/write. Enforced by default.

### Web Panel
- **Local-only web UI** — dark app-style interface (127.0.0.1 only, never exposed to network).
- **Dashboard** — self-test status, AES-NI detection, risk level, feature summary.
- **File browser** — scan for vault files with live entropy analysis.
- **Security probes** — run memory and behavioral probes from the browser.
- **Benchmarks** — AEAD throughput visualization.

### Licensing
- **Machine-bound licenses** — Ed25519 signed, tied to hardware fingerprint, offline validation.
- **Community tier** — free, perpetual, full core functionality.
- **Tamper-evident** — changing any license field invalidates the signature.

---

## Install

### From Source

```bash
git clone https://github.com/yourusername/vault.git
cd vault
cargo build --release
```

Binary: `target/release/vault` (~1.5 MB)

### Requirements

- Rust 1.75+ (stable)
- C compiler (for pqcrypto-kyber FFI)

---

## Usage

### Encrypt with passphrase

```bash
vault encrypt -i secret.txt -p
# Passphrase: ********
# Confirm: ********
# Encrypted: secret.txt -> a7f3b2c1-...-d4e5f6a7.vault
```

### Decrypt

```bash
vault decrypt -i a7f3b2c1-...-d4e5f6a7.vault -p
# Passphrase: ********
# Decrypted: ... -> secret.txt (1234 bytes)
```

### Encrypt with public key

```bash
# Generate identity
vault keygen
# Public key:
# vault-pub-AAAA...

# Encrypt for recipient
vault encrypt -i document.pdf -r "vault-pub-AAAA..."

# Decrypt with identity
vault decrypt -i document.pdf.vault --identity ~/.vault/identity.vkey
```

### Multi-recipient

```bash
vault encrypt -i report.xlsx -p -r "vault-pub-AAAA..." -r "vault-pub-BBBB..."
```

### Audit a vault file

```bash
vault audit -i encrypted.vault
# === Vault File Audit ===
# File:       encrypted.vault
# Size:       16832 bytes
# Format:     VAULT v1.0
# Stanzas:    2
#   [ 0] Passphrase (Argon2id: 512MB, 8 iter, 4 threads)
#   [ 1] Public Key (X25519+ML-KEM-768, 1120 bytes encap)
#
# --- Entropy Analysis ---
# Overall:    7.9489 bits/byte — excellent (indistinguishable from random)
# Chi-squared: 285.4 (excellent)
```

### Benchmark

```bash
vault bench
# === Vault Crypto Benchmark ===
# --- AEAD Throughput ---
#   XChaCha20Poly1305: 800 MB/s
#   Aes256Gcm: 798 MB/s
# --- Hybrid KEM (X25519 + ML-KEM-768) ---
#   Keygen:       94µs/op
#   Encapsulate:  173µs/op
#   Decapsulate:  190µs/op
# --- Hashing ---
#   BLAKE3:   2823 MB/s
```

### Security probes

```bash
vault probe
# === Memory Security Probe Report ===
# [PASS] drop-zeroing
# [PASS] virtual-lock
# [INFO] stack-residue
# [INFO] realloc-scatter
#
# === Forensic Artifact Probe Report ===
# [CLEAN] content-residue
# [CLEAN] filename-residue
# [RESID] timestamp-residue (expected — NTFS limitation)
#
# === Behavioral Profile Report ===
# [NONE] executable size: 1027 KB
# [NONE] ciphertext entropy: 7.95 bits/byte
# No high-risk behavioral patterns detected.
```

### Web panel

```bash
vault panel --port 9090
# Vault panel: http://127.0.0.1:9090
```

### Shamir secret sharing

```bash
# Split a key into 5 shares (any 3 reconstruct)
vault split -i ~/.vault/identity.vkey -k 3 -n 5 -o ./shares/

# Reconstruct
vault combine ./shares/share_01.vshr ./shares/share_03.vshr ./shares/share_05.vshr -o recovered.vkey
```

### Register

```bash
vault register --name "Your Name" --email you@example.com
```

---

## Architecture

```
src/
├── crypto/          # 18 modules
│   ├── aead.rs          XChaCha20-Poly1305 + AES-256-GCM
│   ├── kdf.rs           Argon2id with enforced minimums
│   ├── kem.rs           Hybrid X25519 + ML-KEM-768
│   ├── stream.rs        Chunked streaming AEAD
│   ├── sig.rs           Ed25519 signatures
│   ├── hkdf_util.rs     HKDF-SHA256 derivation
│   ├── shamir.rs        K-of-N secret sharing
│   ├── selftest.rs      FIPS-style known-answer tests
│   ├── search.rs        Encrypted keyword search index
│   ├── rekey.rs         Key rotation without re-encryption
│   ├── honeypot.rs      Tripwire files with fingerprinting
│   ├── canary.rs        Dead-man switch system
│   ├── auditlog.rs      Hash-chained encrypted log
│   ├── pipeline.rs      Multi-pass transformation engine
│   ├── polymorph.rs     Polymorphic output generation
│   ├── compress.rs      Zstd compression
│   ├── archive.rs       Multi-file tar archives
│   └── armor.rs         ASCII armor (base64)
├── memory/          # Secure memory (guard pages, VirtualLock, zeroing)
├── format/          # File format (two-layer header, padding)
├── identity/        # Keypair generation and encrypted storage
├── deniable/        # Multi-passphrase deniable encryption
├── forensic/        # Secure deletion, multi-pass shred
├── metadata/        # Filename/timestamp protection
├── platform/        # Hardware detection, whitelist, entropy, env scoring, config
├── testing/         # Security probes (memory, forensic, behavioral)
├── panel/           # Web UI (Axum + embedded SPA)
├── license/         # Registration, machine fingerprint, signed licenses
└── cli/             # 8 command handlers
```

---

## File Format

Two-layer header design — recipient stanzas in plaintext (for key recovery), metadata encrypted with the file key:

```
VAULT\x00\x01\x00          Magic + version
[stanza_count]              u16 LE
[recipient stanzas...]      Plaintext (type + salt/encap + wrapped file key)
[metadata_nonce]            24 bytes
[encrypted_metadata]        Algorithm, chunk size, filename, original size, hash
[chunked AEAD body]         Per-chunk: nonce || ciphertext+tag || final_flag
```

---

## Algorithms

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Key exchange (classical) | X25519 | RFC 7748 |
| Key exchange (post-quantum) | ML-KEM-768 | FIPS 203 |
| Symmetric encryption | XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha |
| Symmetric encryption (HW) | AES-256-GCM | NIST SP 800-38D |
| Key derivation | Argon2id | RFC 9106 |
| Key expansion | HKDF-SHA256 | RFC 5869 |
| Hashing | BLAKE3 | [blake3.io](https://github.com/BLAKE3-team/BLAKE3) |
| Signatures | Ed25519 | RFC 8032 |
| Secret sharing | Shamir's Secret Sharing | Shamir 1979 |

---

## Tests

```bash
cargo test
# 191 tests, 0 failures, 0 warnings
```

Test coverage includes:
- Known-answer vectors for all crypto primitives
- Round-trip encryption/decryption (passphrase + public key)
- Multi-recipient scenarios
- Wrong key/passphrase rejection
- Tampered ciphertext detection
- Deniable encryption layer isolation
- Honeypot fingerprint embedding/extraction
- Canary creation/verification/expiry
- Audit log append/read/tamper-detection
- Key rotation correctness
- Memory security (drop zeroing, allocation patterns)
- Forensic artifact detection
- License generation/validation/tampering
- Encrypted search index round-trips

---

## Security

- **No secret material in error messages** — deliberate vagueness prevents oracle attacks
- **Constant-time comparisons** — all tag/hash/key comparisons use constant-time equality
- **Enforced KDF minimums** — Argon2id parameters below 64MB rejected at the API level
- **Self-test on every startup** — corrupted binary detected before any crypto operation
- **Path whitelist** — prevents accidental encryption of system files

### Known Limitations

- Stack frames are not zeroed after function return in release builds
- VirtualLock has a ~204KB working set limit — Argon2id's memory exceeds this
- NTFS `$MFT` retains filename history after deletion (use full-disk encryption)
- Guard pages make SecureBuf allocations identifiable in memory dumps

---

## License

MIT OR Apache-2.0
