// entropy/src/models.rs

use serde::{Deserialize, Serialize};

/// Caller provides this to kick off a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Absolute path — either a single file or a directory.
    pub path:        String,
    /// Max file size to read in bytes (default: 32 MB).
    /// Larger files are skipped (noted in result).
    pub max_bytes:   u64,
    /// Recurse into subdirectories when path is a directory.
    pub recursive:   bool,
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            path:      String::new(),
            max_bytes: 32 * 1024 * 1024, // 32 MB
            recursive: true,
        }
    }
}

/// Risk classification based on entropy value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// H > 7.5 — likely packed, encrypted, or compressed
    High,
    /// H 6.5–7.5 — possibly compressed or obfuscated  
    Medium,
    /// H 4.0–6.5 — typical binary/mixed content
    Normal,
    /// H < 4.0 — plaintext or sparse
    Low,
    /// File skipped (too large, permission denied, etc.)
    Skipped,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High    => write!(f, "High — likely packed/encrypted"),
            Self::Medium  => write!(f, "Medium — possibly obfuscated"),
            Self::Normal  => write!(f, "Normal"),
            Self::Low     => write!(f, "Low — plaintext/sparse"),
            Self::Skipped => write!(f, "Skipped"),
        }
    }
}

/// Result for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanResult {
    /// Absolute path of the scanned file.
    pub path:       String,
    /// File size in bytes (0 if skipped).
    pub size_bytes: u64,
    /// Shannon entropy H(X) in bits per byte (0.0–8.0).
    /// None if the file was skipped.
    pub entropy:    Option<f64>,
    /// Risk classification.
    pub risk:       RiskLevel,
    /// MIME-like type guessed from magic bytes.
    pub mime_guess: String,
    /// Human-readable explanation.
    pub note:       String,
}

/// Aggregated summary returned at the end of a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_files:   usize,
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub high_risk:     usize,
    pub medium_risk:   usize,
    /// Individual file results, sorted by entropy descending.
    pub results:       Vec<FileScanResult>,
    /// Total scan duration in milliseconds.
    pub elapsed_ms:    u64,
}
