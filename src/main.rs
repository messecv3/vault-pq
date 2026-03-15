//! Vault CLI — post-quantum hybrid file encryption.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(
    name = "vault",
    about = "Post-quantum hybrid file encryption with metadata protection",
    long_about = "Vault encrypts files using hybrid X25519 + ML-KEM-768 key exchange,\n\
                  XChaCha20-Poly1305 or AES-256-GCM authenticated encryption,\n\
                  Argon2id key derivation, and Ed25519 signatures.\n\n\
                  All crypto primitives are verified on startup via FIPS-style self-tests.",
    version,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new identity (X25519 + ML-KEM-768 keypair)
    Keygen {
        /// Output path for encrypted identity file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Encrypt a file
    Encrypt {
        /// Input file (use - for stdin)
        #[arg(short, long)]
        input: PathBuf,

        /// Output file (default: random UUID.vault)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Encrypt with passphrase
        #[arg(short, long)]
        passphrase: bool,

        /// Recipient public key (repeatable)
        #[arg(short, long)]
        recipient: Vec<String>,

        /// Disable content padding
        #[arg(long)]
        no_padding: bool,

        /// Disable metadata protection
        #[arg(long)]
        no_metadata: bool,

        /// Argon2id memory in MB
        #[arg(long, default_value = "512")]
        argon2_memory: u32,

        /// Argon2id iterations
        #[arg(long, default_value = "8")]
        argon2_time: u32,

        /// Whitelist path pattern (repeatable, regex/glob)
        #[arg(short = 'w', long = "whitelist")]
        whitelist: Vec<String>,

        /// Disable path whitelist
        #[arg(long)]
        no_whitelist: bool,
    },

    /// Decrypt a file
    Decrypt {
        /// Input file
        #[arg(short, long)]
        input: PathBuf,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Decrypt with passphrase
        #[arg(short, long)]
        passphrase: bool,

        /// Path to identity file
        #[arg(long)]
        identity: Option<PathBuf>,

        /// Securely delete input after decryption
        #[arg(long)]
        delete_input: bool,
    },

    /// Inspect a vault file without decrypting
    Audit {
        /// File to audit
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Split a secret into Shamir shares
    Split {
        /// Identity file to split
        #[arg(short, long)]
        input: PathBuf,

        /// Minimum shares needed to reconstruct
        #[arg(short = 'k', long, default_value = "3")]
        threshold: u8,

        /// Total shares to generate
        #[arg(short = 'n', long, default_value = "5")]
        shares: u8,

        /// Output directory for share files
        #[arg(short, long)]
        output_dir: PathBuf,
    },

    /// Reconstruct a secret from Shamir shares
    Combine {
        /// Share files (provide at least threshold)
        #[arg(required = true)]
        share_files: Vec<PathBuf>,

        /// Output path for reconstructed secret
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Run crypto benchmarks
    Bench,

    /// Run security probes (memory, forensic, behavioral analysis)
    Probe {
        /// Probe category: "memory", "forensic", "behavioral", or "all"
        #[arg(default_value = "all")]
        category: String,
    },

    /// Launch the web panel (local only)
    Panel {
        /// Port to listen on
        #[arg(short, long, default_value = "9090")]
        port: u16,
    },

    /// Register for a free Community license
    Register {
        /// Your name
        #[arg(long)]
        name: String,

        /// Your email
        #[arg(long)]
        email: String,

        /// Organization (optional)
        #[arg(long)]
        org: Option<String>,
    },

    /// Show hardware capabilities, license, and run self-tests
    Info,
}

#[tokio::main]
async fn main() {
    // FIPS-style self-test on every invocation
    if let Err(e) = vault::crypto::selftest::run_self_tests() {
        eprintln!("FATAL: {}", e);
        eprintln!("The binary may be corrupted. Refusing to operate.");
        process::exit(99);
    }

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Keygen { output } => {
            vault::cli::keygen::run(output)
        }
        Commands::Encrypt {
            input, output, passphrase, recipient,
            no_padding, no_metadata, argon2_memory, argon2_time,
            whitelist, no_whitelist,
        } => {
            vault::cli::encrypt::run(vault::cli::encrypt::EncryptOptions {
                input, output, passphrase,
                recipients: recipient,
                no_padding, no_metadata,
                argon2_memory_mb: argon2_memory,
                argon2_time,
                whitelist_rules: whitelist,
                no_whitelist,
            })
        }
        Commands::Decrypt {
            input, output, passphrase, identity, delete_input,
        } => {
            vault::cli::decrypt::run(vault::cli::decrypt::DecryptOptions {
                input, output, passphrase, identity, delete_input,
            })
        }
        Commands::Audit { input } => {
            vault::cli::audit::run(input)
        }
        Commands::Split { input, threshold, shares, output_dir } => {
            vault::cli::split::run(input, threshold, shares, output_dir)
        }
        Commands::Combine { share_files, output } => {
            vault::cli::combine::run(share_files, output)
        }
        Commands::Bench => {
            vault::cli::bench::run()
        }
        Commands::Probe { category } => {
            match category.as_str() {
                "memory" => {
                    let results = vault::testing::memory_probe::run_all_probes();
                    vault::testing::memory_probe::print_report(&results);
                }
                "forensic" => {
                    let dir = tempfile::tempdir().expect("cannot create temp dir");
                    let results = vault::testing::forensic_probe::run_all_probes(dir.path());
                    vault::testing::forensic_probe::print_report(&results);
                }
                "behavioral" => {
                    let measurements = vault::testing::behavioral_profile::profile_behavior();
                    vault::testing::behavioral_profile::print_report(&measurements);
                }
                "all" | _ => {
                    eprintln!("=== VAULT SECURITY PROBE SUITE ===\n");

                    let mem_results = vault::testing::memory_probe::run_all_probes();
                    vault::testing::memory_probe::print_report(&mem_results);
                    eprintln!();

                    let dir = tempfile::tempdir().expect("cannot create temp dir");
                    let forensic_results = vault::testing::forensic_probe::run_all_probes(dir.path());
                    vault::testing::forensic_probe::print_report(&forensic_results);
                    eprintln!();

                    let behavioral = vault::testing::behavioral_profile::profile_behavior();
                    vault::testing::behavioral_profile::print_report(&behavioral);
                }
            }
            Ok(())
        }
        Commands::Panel { port } => {
            vault::panel::server::start(port).await
        }
        Commands::Register { name, email, org } => {
            match vault::license::manager::register(&name, &email, org.as_deref()) {
                Ok(license) => {
                    eprintln!("Registered successfully!");
                    eprintln!("  Name:       {}", license.licensee.name);
                    eprintln!("  Email:      {}", license.licensee.email);
                    eprintln!("  Tier:       {}", license.tier);
                    eprintln!("  Machine:    {}", license.machine_id);
                    eprintln!("  Expires:    {}", if license.expires_at == 0 { "never".into() }
                        else { format!("in {} days", (license.expires_at - license.issued_at) / 86400) });
                    eprintln!("  License:    {}", vault::license::manager::license_path().display());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Commands::Info => {
            vault::platform::hardware::print_capabilities();
            eprintln!("Self-tests: passed");
            vault::license::manager::print_status();
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
