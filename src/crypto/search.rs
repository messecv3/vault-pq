//! Encrypted file search — find files by keyword without decrypting them.
//!
//! # How It Works
//!
//! 1. Before encryption, extract searchable tokens from the plaintext
//!    (words, phrases, metadata keywords)
//! 2. Hash each token with BLAKE3 keyed hash (using a search key derived
//!    from the file key via HKDF)
//! 3. Store the hashed tokens in a search index alongside the vault filename
//! 4. To search: hash the query with the same key, match against the index
//!
//! # Security Properties
//!
//! - Tokens are keyed hashes — without the search key, the index reveals nothing
//! - Same word in different files produces the SAME hash (searchable)
//! - The search key is derived from the master passphrase, not the file key
//!   (so one search key works across all files encrypted with that passphrase)
//! - Index does not reveal: word frequency, word position, word length (all
//!   hashed to fixed 32 bytes)
//!
//! # Limitations
//!
//! - Exact match only (no fuzzy/substring search — hashing is all-or-nothing)
//! - Search key compromise reveals which files contain which words
//! - Adding/removing files requires index rebuild for that file

use std::path::Path;
use crate::memory::SecureBuf;
use crate::error::VaultError;

/// A search index entry for one encrypted file.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FileIndexEntry {
    /// Path to the encrypted vault file
    pub vault_path: String,
    /// Original filename (encrypted in the vault, stored here for search results)
    pub original_name: Option<String>,
    /// Set of token hashes (BLAKE3, 32 bytes each, hex-encoded for JSON)
    pub token_hashes: Vec<String>,
    /// File size (original, before encryption)
    pub original_size: u64,
    /// Timestamp when indexed
    pub indexed_at: u64,
}

/// The complete search index.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchIndex {
    /// Version of the index format
    pub version: u32,
    /// All indexed files
    pub entries: Vec<FileIndexEntry>,
}

impl SearchIndex {
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }

    /// Add a file to the index.
    pub fn add_file(
        &mut self,
        vault_path: &str,
        original_name: Option<&str>,
        original_size: u64,
        plaintext: &[u8],
        search_key: &SecureBuf,
    ) {
        // Extract tokens from plaintext
        let tokens = extract_tokens(plaintext);

        // Hash each token
        let token_hashes: Vec<String> = tokens.iter()
            .map(|token| hash_token(token, search_key))
            .collect();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Remove existing entry for this path (re-index)
        self.entries.retain(|e| e.vault_path != vault_path);

        self.entries.push(FileIndexEntry {
            vault_path: vault_path.into(),
            original_name: original_name.map(String::from),
            token_hashes,
            original_size,
            indexed_at: now,
        });
    }

    /// Remove a file from the index.
    pub fn remove_file(&mut self, vault_path: &str) {
        self.entries.retain(|e| e.vault_path != vault_path);
    }

    /// Search for files containing a keyword.
    pub fn search(
        &self,
        query: &str,
        search_key: &SecureBuf,
    ) -> Vec<SearchResult> {
        let query_normalized = normalize_token(query);
        let query_hash = hash_token(&query_normalized, search_key);

        let mut results = Vec::new();
        for entry in &self.entries {
            if entry.token_hashes.contains(&query_hash) {
                results.push(SearchResult {
                    vault_path: entry.vault_path.clone(),
                    original_name: entry.original_name.clone(),
                    original_size: entry.original_size,
                });
            }
        }

        results
    }

    /// Multi-keyword search (AND logic — all keywords must match).
    pub fn search_all(
        &self,
        queries: &[&str],
        search_key: &SecureBuf,
    ) -> Vec<SearchResult> {
        let query_hashes: Vec<String> = queries.iter()
            .map(|q| hash_token(&normalize_token(q), search_key))
            .collect();

        let mut results = Vec::new();
        for entry in &self.entries {
            let all_match = query_hashes.iter()
                .all(|qh| entry.token_hashes.contains(qh));

            if all_match {
                results.push(SearchResult {
                    vault_path: entry.vault_path.clone(),
                    original_name: entry.original_name.clone(),
                    original_size: entry.original_size,
                });
            }
        }

        results
    }

    /// Save index to an encrypted file.
    pub fn save_encrypted(
        &self,
        path: &Path,
        index_key: &SecureBuf,
    ) -> Result<(), VaultError> {
        use crate::crypto::aead;

        let json = serde_json::to_vec(self)
            .map_err(|e| VaultError::InvalidFormat(format!("index serialize: {}", e)))?;

        let mut nonce = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let encrypted = aead::encrypt(
            aead::AeadAlgorithm::XChaCha20Poly1305,
            index_key,
            &nonce,
            b"vault-search-index-v1",
            &json,
        )?;

        let mut output = Vec::new();
        output.extend_from_slice(b"VIDX\x00\x01"); // magic + version
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
        output.extend_from_slice(&encrypted);

        std::fs::write(path, output)?;
        Ok(())
    }

    /// Load index from an encrypted file.
    pub fn load_encrypted(
        path: &Path,
        index_key: &SecureBuf,
    ) -> Result<Self, VaultError> {
        use crate::crypto::aead;

        let data = std::fs::read(path)
            .map_err(|_| VaultError::FileNotFound(path.display().to_string()))?;

        if data.len() < 6 + 24 + 4 || &data[..4] != b"VIDX" {
            return Err(VaultError::InvalidFormat("not a vault search index".into()));
        }

        let nonce = &data[6..30];
        let ct_len = u32::from_le_bytes(data[30..34].try_into().unwrap()) as usize;

        if 34 + ct_len > data.len() {
            return Err(VaultError::InvalidFormat("index truncated".into()));
        }

        let json = aead::decrypt(
            aead::AeadAlgorithm::XChaCha20Poly1305,
            index_key,
            nonce,
            b"vault-search-index-v1",
            &data[34..34 + ct_len],
        )?;

        serde_json::from_slice(&json)
            .map_err(|e| VaultError::InvalidFormat(format!("index deserialize: {}", e)))
    }

    /// Get index statistics.
    pub fn stats(&self) -> IndexStats {
        let total_tokens: usize = self.entries.iter()
            .map(|e| e.token_hashes.len())
            .sum();

        IndexStats {
            file_count: self.entries.len(),
            total_tokens,
            avg_tokens_per_file: if self.entries.is_empty() { 0.0 }
                else { total_tokens as f64 / self.entries.len() as f64 },
        }
    }
}

/// A search result.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchResult {
    pub vault_path: String,
    pub original_name: Option<String>,
    pub original_size: u64,
}

/// Index statistics.
#[derive(Clone, Debug)]
pub struct IndexStats {
    pub file_count: usize,
    pub total_tokens: usize,
    pub avg_tokens_per_file: f64,
}

/// Extract searchable tokens from plaintext content.
/// Tokens are normalized: lowercase, trimmed, deduplicated.
fn extract_tokens(data: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(data);
    let mut tokens: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|w| w.len() >= 3) // Skip very short words
        .map(|w| normalize_token(w))
        .collect();

    tokens.sort();
    tokens.dedup();
    tokens
}

/// Normalize a token for consistent hashing.
fn normalize_token(token: &str) -> String {
    token.trim().to_lowercase()
}

/// Hash a token with the search key using BLAKE3 keyed hash.
fn hash_token(token: &str, search_key: &SecureBuf) -> String {
    let mut key = [0u8; 32];
    key.copy_from_slice(&search_key.expose()[..32]);
    let hash = blake3::keyed_hash(&key, token.as_bytes());
    hex::encode(hash.as_bytes())
}

/// Derive a search key from a passphrase (separate from the encryption key).
pub fn derive_search_key(passphrase: &[u8]) -> Result<SecureBuf, VaultError> {
    crate::crypto::hkdf_util::derive(
        passphrase,
        b"vault-search-key-salt",
        b"vault-search-key-v1",
        32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_search_key() -> SecureBuf {
        derive_search_key(b"test passphrase").unwrap()
    }

    #[test]
    fn test_extract_tokens() {
        let text = b"Hello World! This is a test document with some words.";
        let tokens = extract_tokens(text);
        assert!(tokens.contains(&"hello".to_string()));
        assert!(tokens.contains(&"world".to_string()));
        assert!(tokens.contains(&"document".to_string()));
        // Short words (< 3 chars) excluded
        assert!(!tokens.contains(&"is".to_string()));
        assert!(!tokens.contains(&"a".to_string()));
    }

    #[test]
    fn test_search_finds_file() {
        let key = test_search_key();
        let mut index = SearchIndex::new();

        index.add_file(
            "file1.vault", Some("report.txt"), 1000,
            b"Quarterly revenue report for Q3 2026", &key,
        );
        index.add_file(
            "file2.vault", Some("notes.txt"), 500,
            b"Meeting notes from the board discussion", &key,
        );

        let results = index.search("revenue", &key);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vault_path, "file1.vault");

        let results = index.search("meeting", &key);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].vault_path, "file2.vault");
    }

    #[test]
    fn test_search_no_match() {
        let key = test_search_key();
        let mut index = SearchIndex::new();
        index.add_file("file.vault", None, 100, b"hello world", &key);

        let results = index.search("nonexistent", &key);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_all_keywords() {
        let key = test_search_key();
        let mut index = SearchIndex::new();

        index.add_file("a.vault", None, 100, b"apple banana cherry", &key);
        index.add_file("b.vault", None, 100, b"apple cherry date", &key);
        index.add_file("c.vault", None, 100, b"banana date elderberry", &key);

        let results = index.search_all(&["apple", "cherry"], &key);
        assert_eq!(results.len(), 2); // a.vault and b.vault
    }

    #[test]
    fn test_wrong_key_no_results() {
        let key1 = derive_search_key(b"key one").unwrap();
        let key2 = derive_search_key(b"key two").unwrap();

        let mut index = SearchIndex::new();
        index.add_file("file.vault", None, 100, b"secret document", &key1);

        // Searching with wrong key finds nothing
        let results = index.search("secret", &key2);
        assert!(results.is_empty());
    }

    #[test]
    fn test_case_insensitive() {
        let key = test_search_key();
        let mut index = SearchIndex::new();
        index.add_file("f.vault", None, 100, b"Hello WORLD test", &key);

        assert_eq!(index.search("hello", &key).len(), 1);
        assert_eq!(index.search("HELLO", &key).len(), 1);
        assert_eq!(index.search("Hello", &key).len(), 1);
    }

    #[test]
    fn test_index_save_load() {
        let key = test_search_key();
        let index_key = SecureBuf::random(32).unwrap();

        let mut index = SearchIndex::new();
        index.add_file("test.vault", Some("doc.txt"), 42, b"searchable content here", &key);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vidx");

        index.save_encrypted(&path, &index_key).unwrap();
        let loaded = SearchIndex::load_encrypted(&path, &index_key).unwrap();

        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].vault_path, "test.vault");

        // Search still works on loaded index
        let results = loaded.search("searchable", &key);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_stats() {
        let key = test_search_key();
        let mut index = SearchIndex::new();
        index.add_file("a.vault", None, 100, b"hello world test", &key);
        index.add_file("b.vault", None, 200, b"another document here", &key);

        let stats = index.stats();
        assert_eq!(stats.file_count, 2);
        assert!(stats.total_tokens > 0);
    }
}
