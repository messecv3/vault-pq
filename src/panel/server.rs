//! Axum web server for the Vault panel.
//!
//! Binds to 127.0.0.1 ONLY — never exposed to the network.

use axum::{
    Router,
    routing::get,
    response::Html,
};
use crate::panel::api;
use crate::error::VaultError;

/// Start the web panel server.
pub async fn start(port: u16) -> Result<(), VaultError> {
    let app = Router::new()
        .route("/", get(serve_frontend))
        .route("/api/status", get(api::status))
        .route("/api/entropy", get(api::analyze_entropy))
        .route("/api/probes", get(api::run_probes))
        .route("/api/bench", get(api::quick_bench))
        .route("/api/files", get(api::list_vault_files));

    let addr = format!("127.0.0.1:{}", port);
    eprintln!("Vault panel: http://{}", addr);
    eprintln!("Press Ctrl+C to stop.\n");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| VaultError::PlatformError(format!("bind failed: {}", e)))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| VaultError::PlatformError(format!("server error: {}", e)))?;

    Ok(())
}

async fn serve_frontend() -> Html<&'static str> {
    Html(FRONTEND_HTML)
}

const FRONTEND_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vault</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
    --accent: #58a6ff; --green: #3fb950; --red: #f85149;
    --yellow: #d29922; --purple: #bc8cff;
    --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
  }
  body { font-family: var(--font); background: var(--bg); color: var(--text);
         height: 100vh; display: flex; overflow: hidden; user-select: none; }

  /* Sidebar */
  .sidebar { width: 220px; background: var(--bg2); border-right: 1px solid var(--border);
             display: flex; flex-direction: column; flex-shrink: 0; }
  .sidebar-header { padding: 20px 16px 12px; font-size: 18px; font-weight: 700;
                     letter-spacing: 1.5px; color: var(--accent); }
  .sidebar-header span { font-size: 10px; color: var(--text2); font-weight: 400;
                          display: block; margin-top: 2px; letter-spacing: 0; }
  .nav-item { padding: 10px 16px; cursor: pointer; font-size: 13px;
              color: var(--text2); transition: all 0.15s; display: flex;
              align-items: center; gap: 8px; border-left: 2px solid transparent; }
  .nav-item:hover { background: var(--bg3); color: var(--text); }
  .nav-item.active { color: var(--accent); border-left-color: var(--accent);
                      background: rgba(88,166,255,0.08); }
  .nav-icon { width: 16px; text-align: center; font-size: 14px; }
  .nav-section { padding: 16px 16px 6px; font-size: 10px; text-transform: uppercase;
                  letter-spacing: 1.2px; color: var(--text2); }

  /* Main content */
  .main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .topbar { height: 48px; background: var(--bg2); border-bottom: 1px solid var(--border);
            display: flex; align-items: center; padding: 0 20px; gap: 12px; flex-shrink: 0; }
  .topbar-title { font-size: 14px; font-weight: 600; }
  .topbar-badge { font-size: 10px; padding: 2px 8px; border-radius: 10px;
                   background: var(--bg3); color: var(--text2); }
  .content { flex: 1; overflow-y: auto; padding: 24px; }

  /* Cards */
  .card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
          padding: 20px; margin-bottom: 16px; }
  .card-title { font-size: 13px; font-weight: 600; color: var(--text2);
                text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 12px; }

  /* Grid */
  .grid { display: grid; gap: 16px; }
  .grid-2 { grid-template-columns: 1fr 1fr; }
  .grid-3 { grid-template-columns: 1fr 1fr 1fr; }
  .grid-4 { grid-template-columns: 1fr 1fr 1fr 1fr; }

  /* Stat */
  .stat { text-align: center; }
  .stat-value { font-size: 28px; font-weight: 700; font-family: var(--mono); }
  .stat-label { font-size: 11px; color: var(--text2); margin-top: 4px; }

  /* Status badges */
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px;
           font-weight: 600; }
  .badge-green { background: rgba(63,185,80,0.15); color: var(--green); }
  .badge-red { background: rgba(248,81,73,0.15); color: var(--red); }
  .badge-yellow { background: rgba(210,153,34,0.15); color: var(--yellow); }
  .badge-blue { background: rgba(88,166,255,0.15); color: var(--accent); }

  /* Table */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; color: var(--text2); font-weight: 500;
       border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase;
       letter-spacing: 0.5px; }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  tr:hover td { background: var(--bg3); }

  /* Entropy bar */
  .entropy-bar { height: 6px; background: var(--bg3); border-radius: 3px; overflow: hidden;
                  margin-top: 4px; }
  .entropy-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }

  /* Probe result */
  .probe { padding: 12px; border-radius: 6px; margin-bottom: 8px; background: var(--bg); }
  .probe-header { display: flex; justify-content: space-between; align-items: center; }
  .probe-name { font-weight: 600; font-size: 13px; }
  .probe-desc { font-size: 12px; color: var(--text2); margin-top: 6px; line-height: 1.5; }

  /* Button */
  .btn { padding: 8px 16px; border-radius: 6px; border: 1px solid var(--border);
         background: var(--bg3); color: var(--text); cursor: pointer; font-size: 12px;
         font-family: var(--font); transition: all 0.15s; }
  .btn:hover { border-color: var(--accent); color: var(--accent); }
  .btn-primary { background: var(--accent); color: #0d1117; border-color: var(--accent); }
  .btn-primary:hover { background: #79c0ff; }

  /* Loading */
  .loading { color: var(--text2); font-style: italic; padding: 20px; text-align: center; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 8px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--bg3); border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--border); }

  @media (max-width: 900px) { .grid-3, .grid-4 { grid-template-columns: 1fr 1fr; } }
</style>
</head>
<body>
  <div class="sidebar">
    <div class="sidebar-header">VAULT <span>Post-Quantum Encryption</span></div>
    <div class="nav-section">Overview</div>
    <div class="nav-item active" onclick="showPage('dashboard')">
      <span class="nav-icon">&#9673;</span> Dashboard</div>
    <div class="nav-item" onclick="showPage('files')">
      <span class="nav-icon">&#128196;</span> Files</div>
    <div class="nav-section">Analysis</div>
    <div class="nav-item" onclick="showPage('entropy')">
      <span class="nav-icon">&#128200;</span> Entropy</div>
    <div class="nav-item" onclick="showPage('probes')">
      <span class="nav-icon">&#128737;</span> Security Probes</div>
    <div class="nav-item" onclick="showPage('bench')">
      <span class="nav-icon">&#9889;</span> Benchmark</div>
  </div>

  <div class="main">
    <div class="topbar">
      <div class="topbar-title" id="page-title">Dashboard</div>
      <div id="topbar-badges"></div>
    </div>
    <div class="content" id="content">
      <div class="loading">Loading...</div>
    </div>
  </div>

<script>
const API = '';

async function fetchJSON(url) {
  const r = await fetch(API + url);
  return r.json();
}

function showPage(page) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  event.target.closest('.nav-item').classList.add('active');
  document.getElementById('page-title').textContent =
    page.charAt(0).toUpperCase() + page.slice(1);

  const handlers = { dashboard: loadDashboard, files: loadFiles,
                      entropy: loadEntropy, probes: loadProbes, bench: loadBench };
  (handlers[page] || loadDashboard)();
}

async function loadDashboard() {
  const c = document.getElementById('content');
  c.innerHTML = '<div class="loading">Loading status...</div>';

  const status = await fetchJSON('/api/status');

  c.innerHTML = `
    <div class="grid grid-4" style="margin-bottom:20px">
      <div class="card stat">
        <div class="stat-value" style="color:var(--green)">${status.self_test === 'passed' ? 'OK' : 'FAIL'}</div>
        <div class="stat-label">Self-Test</div>
      </div>
      <div class="card stat">
        <div class="stat-value" style="color:${status.aes_ni ? 'var(--green)' : 'var(--yellow)'}">${status.aes_ni ? 'YES' : 'NO'}</div>
        <div class="stat-label">AES-NI</div>
      </div>
      <div class="card stat">
        <div class="stat-value" style="color:var(--accent)">${status.platform}</div>
        <div class="stat-label">Architecture</div>
      </div>
      <div class="card stat">
        <div class="stat-value" style="color:${status.risk_level === 'LOW' ? 'var(--green)' : 'var(--yellow)'}">${status.risk_level}</div>
        <div class="stat-label">Env Risk</div>
      </div>
    </div>
    <div class="grid grid-2">
      <div class="card">
        <div class="card-title">System Info</div>
        <table>
          <tr><td style="color:var(--text2)">Version</td><td>${status.version}</td></tr>
          <tr><td style="color:var(--text2)">AES-NI</td><td>${status.aes_ni ? '<span class="badge badge-green">Available</span>' : '<span class="badge badge-yellow">Software</span>'}</td></tr>
          <tr><td style="color:var(--text2)">Self-Test</td><td>${status.self_test === 'passed' ? '<span class="badge badge-green">Passed</span>' : '<span class="badge badge-red">Failed</span>'}</td></tr>
          <tr><td style="color:var(--text2)">Risk Level</td><td>${status.risk_level}</td></tr>
        </table>
      </div>
      <div class="card">
        <div class="card-title">Features</div>
        <table>
          <tr><td style="color:var(--text2)">Encryption</td><td>XChaCha20 / AES-256-GCM</td></tr>
          <tr><td style="color:var(--text2)">Key Exchange</td><td>X25519 + ML-KEM-768</td></tr>
          <tr><td style="color:var(--text2)">KDF</td><td>Argon2id</td></tr>
          <tr><td style="color:var(--text2)">Signatures</td><td>Ed25519</td></tr>
          <tr><td style="color:var(--text2)">Hashing</td><td>BLAKE3 / SHA-256</td></tr>
        </table>
      </div>
    </div>`;
}

async function loadFiles() {
  const c = document.getElementById('content');
  c.innerHTML = '<div class="loading">Scanning for vault files...</div>';

  const data = await fetchJSON('/api/files?dir=.');

  if (data.files.length === 0) {
    c.innerHTML = '<div class="card"><div class="card-title">Vault Files</div><p style="color:var(--text2)">No .vault files found in current directory.</p></div>';
    return;
  }

  let rows = data.files.map(f => {
    const ent = f.entropy.toFixed(2);
    const entColor = f.entropy > 7.9 ? 'var(--green)' : f.entropy > 7.0 ? 'var(--yellow)' : 'var(--red)';
    const sizeKB = (f.size / 1024).toFixed(1);
    return `<tr>
      <td style="font-family:var(--mono);font-size:12px">${f.path}</td>
      <td>${sizeKB} KB</td>
      <td><span style="color:${entColor}">${ent}</span>
        <div class="entropy-bar"><div class="entropy-fill" style="width:${(f.entropy/8*100).toFixed(0)}%;background:${entColor}"></div></div>
      </td>
    </tr>`;
  }).join('');

  c.innerHTML = `<div class="card"><div class="card-title">Vault Files (${data.files.length})</div>
    <table><tr><th>Path</th><th>Size</th><th>Entropy</th></tr>${rows}</table></div>`;
}

async function loadEntropy() {
  const c = document.getElementById('content');
  c.innerHTML = `<div class="card"><div class="card-title">Entropy Analysis</div>
    <p style="color:var(--text2);margin-bottom:12px">Select a vault file from the Files tab, or analyze a file by path.</p>
    <p style="color:var(--text2);font-size:12px">Well-encrypted data: 7.9+ bits/byte<br>
    Compressed data: 7.0-7.9 bits/byte<br>Plaintext: 4.0-6.5 bits/byte</p></div>`;
}

async function loadProbes() {
  const c = document.getElementById('content');
  c.innerHTML = '<div class="loading">Running security probes...</div>';

  const [mem, beh] = await Promise.all([
    fetchJSON('/api/probes?category=memory'),
    fetchJSON('/api/probes?category=behavioral'),
  ]);

  let memProbes = mem.results.map(r => {
    const color = r.severity === 'Pass' ? 'var(--green)' : r.severity === 'Critical' ? 'var(--red)' : 'var(--yellow)';
    return `<div class="probe">
      <div class="probe-header">
        <span class="probe-name">${r.name}</span>
        <span class="badge" style="background:${color}20;color:${color}">${r.status}</span>
      </div>
      <div class="probe-desc">${r.description}</div>
    </div>`;
  }).join('');

  let behProbes = beh.results.map(r => {
    const color = r.severity === 'None' ? 'var(--green)' : r.severity === 'Low' ? 'var(--yellow)' : 'var(--red)';
    return `<div class="probe">
      <div class="probe-header">
        <span class="probe-name">${r.name}</span>
        <span class="badge" style="background:${color}20;color:${color}">${r.severity}</span>
      </div>
      <div class="probe-desc">${r.description}</div>
    </div>`;
  }).join('');

  c.innerHTML = `
    <div class="card"><div class="card-title">Memory Security</div>${memProbes}</div>
    <div class="card"><div class="card-title">Behavioral Profile</div>${behProbes}</div>`;
}

async function loadBench() {
  const c = document.getElementById('content');
  c.innerHTML = '<div class="loading">Running benchmarks...</div>';

  const data = await fetchJSON('/api/bench');

  let bars = data.map(b => {
    const maxMbps = Math.max(...data.map(d => d.throughput_mbps));
    const pct = (b.throughput_mbps / maxMbps * 100).toFixed(0);
    return `<div style="margin-bottom:16px">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <span style="font-size:13px">${b.algorithm}</span>
        <span style="font-family:var(--mono);color:var(--accent)">${b.throughput_mbps.toFixed(0)} MB/s</span>
      </div>
      <div class="entropy-bar" style="height:10px">
        <div class="entropy-fill" style="width:${pct}%;background:var(--accent)"></div>
      </div>
    </div>`;
  }).join('');

  c.innerHTML = `<div class="card"><div class="card-title">AEAD Throughput (1MB blocks)</div>${bars}</div>`;
}

// Load dashboard on start
loadDashboard();
</script>
</body>
</html>
"##;
