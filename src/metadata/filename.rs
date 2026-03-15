//! Filename protection — replace real filenames with random UUIDs.

use uuid::Uuid;

/// Generate a random output filename with the given extension.
pub fn random_filename(extension: &str) -> String {
    format!("{}.{}", Uuid::new_v4(), extension)
}

/// Generate a random filename with the default vault extension.
pub fn random_vault_filename() -> String {
    random_filename("vault")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_filenames_are_unique() {
        let a = random_vault_filename();
        let b = random_vault_filename();
        assert_ne!(a, b);
    }

    #[test]
    fn test_extension() {
        let name = random_filename("enc");
        assert!(name.ends_with(".enc"));
    }
}
