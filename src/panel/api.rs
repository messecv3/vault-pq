//! REST API handlers for the web panel.

use axum::{
    extract::Query,
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use crate::crypto::aead;
use crate::platform::{entropy, environment, hardware};
use crate::memory::SecureBuf;

// === Response Types ===

#[derive(Serialize)]
pub struct StatusResponse {
    pub version: &'static str,
    pub aes_ni: bool,
    pub platform: &'static str,
    pub risk_level: String,
    pub self_test: String,
}

#[derive(Serialize)]
pub struct EntropyResponse {
    pub entropy: f64,
    pub classification: String,
    pub chi_squared: f64,
    pub file_size: u64,
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub query: String,
    pub results: Vec<SearchResultItem>,
    pub total: usize,
}

#[derive(Serialize)]
pub struct SearchResultItem {
    pub vault_path: String,
    pub original_name: Option<String>,
    pub original_size: u64,
}

#[derive(Serialize)]
pub struct ProbeResponse {
    pub category: String,
    pub results: Vec<ProbeItem>,
}

#[derive(Serialize)]
pub struct ProbeItem {
    pub name: String,
    pub status: String,
    pub description: String,
    pub severity: String,
}

#[derive(Serialize)]
pub struct FileListResponse {
    pub files: Vec<FileEntry>,
}

#[derive(Serialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub entropy: f64,
}

#[derive(Serialize)]
pub struct BenchResponse {
    pub algorithm: String,
    pub throughput_mbps: f64,
}

// === Query Parameters ===

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub key: Option<String>,
}

#[derive(Deserialize)]
pub struct FileQuery {
    pub path: String,
}

// === Handlers ===

pub async fn status() -> Json<StatusResponse> {
    let self_test = match crate::crypto::selftest::run_self_tests() {
        Ok(()) => "passed".to_string(),
        Err(e) => format!("FAILED: {}", e),
    };

    let assessment = environment::assess_environment();

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        aes_ni: hardware::has_aes_ni(),
        platform: std::env::consts::ARCH,
        risk_level: format!("{}", assessment.risk_level),
        self_test,
    })
}

pub async fn analyze_entropy(Query(params): Query<FileQuery>) -> Result<Json<EntropyResponse>, StatusCode> {
    let data = std::fs::read(&params.path)
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let ent = entropy::shannon_entropy(&data);
    let chi2 = entropy::chi_squared(&data);

    Ok(Json(EntropyResponse {
        entropy: ent,
        classification: entropy::classify_entropy(ent).to_string(),
        chi_squared: chi2,
        file_size: data.len() as u64,
    }))
}

pub async fn run_probes(Query(params): Query<CategoryQuery>) -> Json<ProbeResponse> {
    let category = params.category.unwrap_or_else(|| "memory".into());

    let items = match category.as_str() {
        "memory" => {
            crate::testing::memory_probe::run_all_probes()
                .into_iter()
                .map(|r| ProbeItem {
                    name: r.test_name.to_string(),
                    status: if r.passed { "pass" } else { "fail" }.into(),
                    description: r.description,
                    severity: format!("{:?}", r.severity),
                })
                .collect()
        }
        "behavioral" => {
            crate::testing::behavioral_profile::profile_behavior()
                .into_iter()
                .map(|m| ProbeItem {
                    name: m.metric,
                    status: format!("{:?}", m.detection_risk),
                    description: m.explanation,
                    severity: format!("{:?}", m.detection_risk),
                })
                .collect()
        }
        _ => Vec::new(),
    };

    Json(ProbeResponse {
        category,
        results: items,
    })
}

#[derive(Deserialize)]
pub struct CategoryQuery {
    pub category: Option<String>,
}

pub async fn quick_bench() -> Json<Vec<BenchResponse>> {
    let key = SecureBuf::random(32).unwrap();
    let data = vec![0x42u8; 1_048_576]; // 1MB
    let mut results = Vec::new();

    for algo in &[aead::AeadAlgorithm::XChaCha20Poly1305, aead::AeadAlgorithm::Aes256Gcm] {
        let nonce = vec![0u8; algo.nonce_size()];
        let start = std::time::Instant::now();
        let iterations = 20;

        for _ in 0..iterations {
            let _ = aead::encrypt(*algo, &key, &nonce, b"", &data);
        }

        let elapsed = start.elapsed();
        let mbps = (iterations as f64 * data.len() as f64) / elapsed.as_secs_f64() / 1_048_576.0;

        results.push(BenchResponse {
            algorithm: format!("{:?}", algo),
            throughput_mbps: mbps,
        });
    }

    Json(results)
}

pub async fn list_vault_files(Query(params): Query<DirQuery>) -> Result<Json<FileListResponse>, StatusCode> {
    let dir = params.dir.unwrap_or_else(|| ".".into());
    let path = std::path::Path::new(&dir);

    if !path.is_dir() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("vault") {
                if let Ok(meta) = std::fs::metadata(&p) {
                    let data = std::fs::read(&p).unwrap_or_default();
                    let ent = if data.len() > 100 {
                        entropy::shannon_entropy(&data[..data.len().min(4096)])
                    } else {
                        0.0
                    };

                    files.push(FileEntry {
                        path: p.display().to_string(),
                        size: meta.len(),
                        entropy: ent,
                    });
                }
            }
        }
    }

    Ok(Json(FileListResponse { files }))
}

#[derive(Deserialize)]
pub struct DirQuery {
    pub dir: Option<String>,
}
