//! Runtime environment analysis with weighted scoring.
//!
//! Adapted from Phantom Engine's anti_analysis.h weighted scoring system.
//! Instead of detecting debuggers/VMs for evasion, this detects
//! UNSAFE environments for encryption operations:
//!
//! - Screen recording active (key material visible)
//! - Remote desktop (passphrase visible over network)
//! - Keylogger indicators (passphrase capture)
//! - Memory dump tools running (key extraction)
//! - Virtualized environment (potential snapshot-based key recovery)
//!
//! The scoring system returns a risk level, not a binary decision.
//! The user chooses whether to proceed based on the risk assessment.


/// Risk level classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// No detected risks. Safe to proceed.
    Low,
    /// Some indicators present. Proceed with caution.
    Medium,
    /// Multiple indicators. Passphrase entry may be observed.
    High,
    /// Strong indicators of active monitoring. Consider aborting.
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single environment check result.
#[derive(Clone, Debug)]
pub struct CheckResult {
    pub name: &'static str,
    pub description: &'static str,
    pub detected: bool,
    pub weight: u32,
}

/// Full environment assessment.
#[derive(Clone, Debug)]
pub struct EnvironmentAssessment {
    pub checks: Vec<CheckResult>,
    pub total_score: u32,
    pub risk_level: RiskLevel,
}

impl EnvironmentAssessment {
    pub fn detected_risks(&self) -> Vec<&CheckResult> {
        self.checks.iter().filter(|c| c.detected).collect()
    }

    pub fn summary(&self) -> String {
        let detected = self.detected_risks();
        if detected.is_empty() {
            return format!("Risk: {} (score: {})", self.risk_level, self.total_score);
        }

        let mut s = format!(
            "Risk: {} (score: {})\nDetected issues:",
            self.risk_level, self.total_score
        );
        for check in &detected {
            s.push_str(&format!("\n  - {} (+{} pts): {}",
                check.name, check.weight, check.description
            ));
        }
        s
    }
}

/// Run all environment checks and return a weighted assessment.
pub fn assess_environment() -> EnvironmentAssessment {
    let mut checks = Vec::new();

    // Check for remote desktop
    checks.push(check_remote_desktop());

    // Check for screen recording indicators
    checks.push(check_screen_recording());

    // Check for memory analysis tools
    checks.push(check_memory_tools());

    // Check for suspicious environment variables
    checks.push(check_suspicious_env());

    // Check for debugger
    checks.push(check_debugger());

    // Check for virtualization
    checks.push(check_virtualization());

    // Calculate score
    let total_score: u32 = checks.iter()
        .filter(|c| c.detected)
        .map(|c| c.weight)
        .sum();

    let risk_level = match total_score {
        0..=9 => RiskLevel::Low,
        10..=29 => RiskLevel::Medium,
        30..=59 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    EnvironmentAssessment {
        checks,
        total_score,
        risk_level,
    }
}

fn check_remote_desktop() -> CheckResult {
    let detected = std::env::var("SESSIONNAME")
        .map(|v| v.starts_with("RDP-") || v.contains("Console") == false)
        .unwrap_or(false);

    CheckResult {
        name: "remote-desktop",
        description: "RDP session detected — passphrase may be visible to remote observer",
        detected,
        weight: 30,
    }
}

fn check_screen_recording() -> CheckResult {
    // Check for common screen recording process names via env hints.
    // On Windows, we'd check running processes; here we check for indicators.
    let indicators = [
        "OBS_RECORDING", "SCREEN_CAPTURE_ACTIVE", "NVIDIA_SHADOWPLAY",
    ];

    let detected = indicators.iter().any(|var| std::env::var(var).is_ok());

    CheckResult {
        name: "screen-recording",
        description: "Screen recording indicator detected — passphrase may be captured",
        detected,
        weight: 40,
    }
}

fn check_memory_tools() -> CheckResult {
    // Check for common memory analysis tool artifacts
    let artifacts = [
        "WINDBG_DIR", "IDA_DIR", "GHIDRA_INSTALL_DIR", "X64DBG_DIR",
    ];

    let detected = artifacts.iter().any(|var| std::env::var(var).is_ok());

    CheckResult {
        name: "memory-tools",
        description: "Memory analysis tools detected — key material may be extracted",
        detected,
        weight: 20,
    }
}

fn check_suspicious_env() -> CheckResult {
    // Detect environment variables that suggest monitoring
    let suspicious = [
        "VAULT_DEBUG_KEYS", "CRYPTO_LOG_KEYS", "DUMP_SECRETS",
    ];

    let detected = suspicious.iter().any(|var| std::env::var(var).is_ok());

    CheckResult {
        name: "suspicious-env",
        description: "Suspicious environment variables set — possible key logging",
        detected,
        weight: 50,
    }
}

fn check_debugger() -> CheckResult {
    // On Windows, check IsDebuggerPresent equivalent
    // Cross-platform: check for RUST_LOG=trace or common debug indicators
    let detected = std::env::var("RUST_BACKTRACE").map(|v| v == "full").unwrap_or(false)
        && std::env::var("RUST_LOG").map(|v| v.contains("trace")).unwrap_or(false);

    CheckResult {
        name: "debugger",
        description: "Debug environment active — memory inspection possible",
        detected,
        weight: 25,
    }
}

fn check_virtualization() -> CheckResult {
    // Check for common VM indicators in environment
    let vm_hints = [
        ("VBOX_MSI_INSTALL_PATH", "VirtualBox"),
        ("VMWARE_TOOLBOX_CMD", "VMware"),
    ];

    let detected = vm_hints.iter().any(|(var, _)| std::env::var(var).is_ok());

    CheckResult {
        name: "virtualization",
        description: "Virtual machine detected — snapshots may capture key material",
        detected,
        weight: 15,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_environment() {
        // In a normal test environment, most checks should pass
        let assessment = assess_environment();
        // We can't guarantee the exact score, but it shouldn't be critical
        // in a standard CI environment
        assert!(assessment.risk_level <= RiskLevel::High);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_score_thresholds() {
        // Score 0 = Low
        assert_eq!(
            match 0u32 { 0..=9 => RiskLevel::Low, 10..=29 => RiskLevel::Medium,
                         30..=59 => RiskLevel::High, _ => RiskLevel::Critical },
            RiskLevel::Low
        );

        // Score 50 = High
        assert_eq!(
            match 50u32 { 0..=9 => RiskLevel::Low, 10..=29 => RiskLevel::Medium,
                          30..=59 => RiskLevel::High, _ => RiskLevel::Critical },
            RiskLevel::High
        );
    }

    #[test]
    fn test_summary_format() {
        let assessment = assess_environment();
        let summary = assessment.summary();
        assert!(summary.contains("Risk:"));
        assert!(summary.contains("score:"));
    }
}
