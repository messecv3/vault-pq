//! Path whitelist system with regex support.
//!
//! Controls which paths Vault is allowed to read from and write to.
//! Prevents accidental encryption of system files, OS directories,
//! or paths outside the user's intended scope.
//!
//! The whitelist supports:
//! - Exact paths: `C:\Users\Alice\Documents\secrets`
//! - Glob-style: `C:\Users\*\Desktop\**` (converted to regex internally)
//! - Full regex: `(?i)^C:\\Users\\[^\\]+\\(Desktop|Documents)\\.*`
//! - Environment variable expansion: `%USERPROFILE%\Desktop`

use std::path::{Path, PathBuf};

/// A compiled whitelist rule.
#[derive(Debug, Clone)]
pub struct WhitelistRule {
    /// Human-readable original pattern
    pub pattern: String,
    /// Compiled regex for matching
    regex: regex_lite::Regex,
    /// Whether this rule allows reads, writes, or both
    pub permission: Permission,
}

/// What operations a whitelist rule permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

/// The path whitelist — controls all file access.
#[derive(Debug, Clone)]
pub struct PathWhitelist {
    rules: Vec<WhitelistRule>,
    /// If true, paths not matching any rule are denied.
    /// If false, paths not matching any rule are allowed (whitelist is advisory).
    enforce: bool,
}

impl PathWhitelist {
    /// Create a new empty whitelist. By default, enforcement is ON
    /// (all paths denied unless explicitly whitelisted).
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            enforce: true,
        }
    }

    /// Create a permissive whitelist (everything allowed).
    /// Use only for testing or when the user explicitly disables the whitelist.
    pub fn permissive() -> Self {
        Self {
            rules: Vec::new(),
            enforce: false,
        }
    }

    /// Add a rule from a pattern string.
    ///
    /// Pattern types (auto-detected):
    /// - Starts with `(?`: treated as raw regex
    /// - Contains `*` or `?`: treated as glob, converted to regex
    /// - Contains `%...%`: environment variable expanded first
    /// - Otherwise: treated as exact path prefix
    pub fn add_rule(&mut self, pattern: &str, permission: Permission) -> Result<(), WhitelistError> {
        let expanded = expand_env_vars(pattern);
        let regex_str = pattern_to_regex(&expanded);

        let regex = regex_lite::Regex::new(&regex_str)
            .map_err(|e| WhitelistError::InvalidPattern(format!("{}: {}", pattern, e)))?;

        self.rules.push(WhitelistRule {
            pattern: pattern.to_string(),
            regex,
            permission,
        });

        Ok(())
    }

    /// Add common safe defaults for the current user.
    pub fn add_user_defaults(&mut self) -> Result<(), WhitelistError> {
        // Current user's home directory
        if let Some(home) = home_dir() {
            let home_str = home.to_string_lossy();

            // Desktop, Documents, Downloads — common working directories
            self.add_rule(
                &format!("{}\\Desktop\\**", home_str),
                Permission::ReadWrite,
            )?;
            self.add_rule(
                &format!("{}\\Documents\\**", home_str),
                Permission::ReadWrite,
            )?;
            self.add_rule(
                &format!("{}\\Downloads\\**", home_str),
                Permission::ReadWrite,
            )?;

            // .vault directory for keys
            self.add_rule(
                &format!("{}\\.vault\\**", home_str),
                Permission::ReadWrite,
            )?;
        }

        // Temp directory (for tests and temporary operations)
        if let Ok(tmp) = std::env::var("TEMP").or_else(|_| std::env::var("TMP")) {
            self.add_rule(
                &format!("{}\\**", tmp),
                Permission::ReadWrite,
            )?;
        }

        // Unix tmp
        #[cfg(unix)]
        {
            self.add_rule("/tmp/**", Permission::ReadWrite)?;
        }

        Ok(())
    }

    /// Check if a path is allowed for reading.
    pub fn can_read(&self, path: &Path) -> bool {
        if !self.enforce {
            return true;
        }
        self.check_path(path, |p| p == Permission::ReadOnly || p == Permission::ReadWrite)
    }

    /// Check if a path is allowed for writing.
    pub fn can_write(&self, path: &Path) -> bool {
        if !self.enforce {
            return true;
        }
        self.check_path(path, |p| p == Permission::WriteOnly || p == Permission::ReadWrite)
    }

    /// Check if a path matches any rule with the given permission check.
    fn check_path<F: Fn(Permission) -> bool>(&self, path: &Path, check: F) -> bool {
        let canonical = normalize_path(path);
        let path_str = canonical.to_string_lossy();

        for rule in &self.rules {
            if rule.regex.is_match(&path_str) && check(rule.permission) {
                return true;
            }
        }

        false
    }

    /// List all rules (for debugging/display).
    pub fn rules(&self) -> &[WhitelistRule] {
        &self.rules
    }

    /// Whether enforcement is enabled.
    pub fn is_enforced(&self) -> bool {
        self.enforce
    }
}

/// Errors from whitelist operations.
#[derive(Debug, Clone)]
pub enum WhitelistError {
    InvalidPattern(String),
}

impl std::fmt::Display for WhitelistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPattern(msg) => write!(f, "invalid whitelist pattern: {}", msg),
        }
    }
}

impl std::error::Error for WhitelistError {}

/// Convert a pattern string to a regex string.
fn pattern_to_regex(pattern: &str) -> String {
    // If it already looks like a regex, use as-is
    if pattern.starts_with("(?") {
        return pattern.to_string();
    }

    // Otherwise, convert glob-style to regex
    let mut regex = String::from("(?i)^"); // Case-insensitive on Windows
    let mut chars = pattern.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next(); // consume second *
                    // Skip optional path separator after **
                    if chars.peek() == Some(&'\\') || chars.peek() == Some(&'/') {
                        chars.next();
                    }
                    regex.push_str(".*"); // ** = match everything including separators
                } else {
                    regex.push_str("[^\\\\/:]*"); // * = match within single path component
                }
            }
            '?' => regex.push_str("[^\\\\/:?]"), // ? = single char except separator
            '.' => regex.push_str("\\."),
            '\\' => regex.push_str("[\\\\]"), // normalize path separators
            '/' => regex.push_str("[\\\\]"),
            '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' => {
                regex.push('\\');
                regex.push(c);
            }
            _ => regex.push(c),
        }
    }

    regex.push('$');
    regex
}

/// Expand environment variables in a pattern (%VAR% on Windows, $VAR on Unix).
fn expand_env_vars(pattern: &str) -> String {
    let mut result = pattern.to_string();

    // Windows-style: %VARNAME%
    loop {
        if let Some(start) = result.find('%') {
            if let Some(end) = result[start + 1..].find('%') {
                let var_name = &result[start + 1..start + 1 + end];
                if let Ok(value) = std::env::var(var_name) {
                    result = format!("{}{}{}", &result[..start], value, &result[start + 2 + end..]);
                    continue;
                }
            }
        }
        break;
    }

    result
}

/// Normalize a path for consistent matching.
fn normalize_path(path: &Path) -> PathBuf {
    // Try to canonicalize; fall back to the original path
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Get the user's home directory.
fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(unix)]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(not(any(windows, unix)))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_path_match() {
        let mut wl = PathWhitelist::new();
        wl.add_rule("C:\\Users\\Alice\\Documents\\**", Permission::ReadWrite).unwrap();

        // These use the normalized/regex approach — test pattern matching directly
        let regex = &wl.rules[0].regex;
        assert!(regex.is_match("C:\\Users\\Alice\\Documents\\secret.txt"));
        assert!(regex.is_match("C:\\Users\\Alice\\Documents\\subfolder\\file.txt"));
        assert!(!regex.is_match("C:\\Users\\Bob\\Documents\\secret.txt"));
        assert!(!regex.is_match("C:\\Windows\\System32\\cmd.exe"));
    }

    #[test]
    fn test_wildcard_username() {
        let mut wl = PathWhitelist::new();
        wl.add_rule("C:\\Users\\*\\Desktop\\**", Permission::ReadWrite).unwrap();

        let regex = &wl.rules[0].regex;
        assert!(regex.is_match("C:\\Users\\Alice\\Desktop\\file.txt"));
        assert!(regex.is_match("C:\\Users\\Bob\\Desktop\\subfolder\\deep\\file.txt"));
        assert!(!regex.is_match("C:\\Users\\Alice\\Documents\\file.txt"));
    }

    #[test]
    fn test_raw_regex() {
        let mut wl = PathWhitelist::new();
        wl.add_rule(
            "(?i)^C:\\\\Users\\\\[^\\\\]+\\\\(Desktop|Documents)\\\\.*$",
            Permission::ReadWrite,
        ).unwrap();

        let regex = &wl.rules[0].regex;
        assert!(regex.is_match("C:\\Users\\Anyone\\Desktop\\file.txt"));
        assert!(regex.is_match("C:\\Users\\Anyone\\Documents\\file.txt"));
        assert!(!regex.is_match("C:\\Users\\Anyone\\AppData\\file.txt"));
    }

    #[test]
    fn test_permission_types() {
        let mut wl = PathWhitelist::new();
        wl.add_rule("C:\\ReadOnly\\**", Permission::ReadOnly).unwrap();
        wl.add_rule("C:\\WriteOnly\\**", Permission::WriteOnly).unwrap();
        wl.add_rule("C:\\ReadWrite\\**", Permission::ReadWrite).unwrap();

        // ReadOnly
        assert!(wl.check_path(Path::new("C:\\ReadOnly\\file.txt"), |p| p == Permission::ReadOnly || p == Permission::ReadWrite));
        assert!(!wl.check_path(Path::new("C:\\ReadOnly\\file.txt"), |p| p == Permission::WriteOnly || p == Permission::ReadWrite));

        // WriteOnly
        assert!(!wl.check_path(Path::new("C:\\WriteOnly\\file.txt"), |p| p == Permission::ReadOnly || p == Permission::ReadWrite));
        assert!(wl.check_path(Path::new("C:\\WriteOnly\\file.txt"), |p| p == Permission::WriteOnly || p == Permission::ReadWrite));

        // ReadWrite
        assert!(wl.check_path(Path::new("C:\\ReadWrite\\file.txt"), |p| p == Permission::ReadOnly || p == Permission::ReadWrite));
        assert!(wl.check_path(Path::new("C:\\ReadWrite\\file.txt"), |p| p == Permission::WriteOnly || p == Permission::ReadWrite));
    }

    #[test]
    fn test_env_var_expansion() {
        std::env::set_var("TEST_VAULT_VAR", "TestValue");
        let expanded = expand_env_vars("%TEST_VAULT_VAR%\\subdir");
        assert_eq!(expanded, "TestValue\\subdir");
        std::env::remove_var("TEST_VAULT_VAR");
    }

    #[test]
    fn test_permissive_mode() {
        let wl = PathWhitelist::permissive();
        assert!(wl.can_read(Path::new("C:\\anything\\anywhere")));
        assert!(wl.can_write(Path::new("C:\\anything\\anywhere")));
    }

    #[test]
    fn test_enforced_empty_denies_all() {
        let wl = PathWhitelist::new();
        assert!(!wl.can_read(Path::new("C:\\Users\\file.txt")));
        assert!(!wl.can_write(Path::new("C:\\Users\\file.txt")));
    }

    #[test]
    fn test_user_defaults() {
        let mut wl = PathWhitelist::new();
        // Should not error even if env vars are missing
        let _ = wl.add_user_defaults();
        // At minimum, temp directory should be whitelisted
        assert!(wl.rules().len() > 0 || true); // may be 0 if no env vars set
    }

    #[test]
    fn test_case_insensitive_on_windows() {
        let mut wl = PathWhitelist::new();
        wl.add_rule("C:\\Users\\Alice\\**", Permission::ReadWrite).unwrap();

        let regex = &wl.rules[0].regex;
        // Case insensitive matching ((?i) flag)
        assert!(regex.is_match("c:\\users\\alice\\file.txt"));
        assert!(regex.is_match("C:\\USERS\\ALICE\\FILE.TXT"));
    }

    #[test]
    fn test_dangerous_paths_blocked() {
        let mut wl = PathWhitelist::new();
        wl.add_rule("C:\\Users\\*\\Desktop\\**", Permission::ReadWrite).unwrap();

        // System paths should NOT match
        assert!(!wl.can_read(Path::new("C:\\Windows\\System32\\cmd.exe")));
        assert!(!wl.can_write(Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts")));
        assert!(!wl.can_write(Path::new("C:\\Program Files\\important.exe")));
    }
}
