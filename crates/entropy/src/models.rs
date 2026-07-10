use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest { pub path: String, pub max_bytes: u64, pub recursive: bool }

impl Default for ScanRequest {
    fn default() -> Self { Self { path: String::new(), max_bytes: 32 * 1024 * 1024, recursive: true } }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel { High, Medium, Normal, Low, Skipped }

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::High => write!(f, "High — likely packed/encrypted"),
            Self::Medium => write!(f, "Medium — possibly obfuscated"),
            Self::Normal => write!(f, "Normal"),
            Self::Low => write!(f, "Low — plaintext/sparse"),
            Self::Skipped => write!(f, "Skipped"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScanResult { pub path: String, pub size_bytes: u64, pub entropy: Option<f64>, pub risk: RiskLevel, pub mime_guess: String, pub note: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary { pub total_files: usize, pub scanned_files: usize, pub skipped_files: usize, pub high_risk: usize, pub medium_risk: usize, pub results: Vec<FileScanResult>, pub elapsed_ms: u64 }
