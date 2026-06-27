// updater/src/lib.rs — GitHub release version checker
//
// Phase 1: version check only (no auto-download).
// Phase 2: background download + BLAKE3 checksum verify + atomic replace.
//
// Called from Tauri command on:
//   • App launch
//   • Every 24 hours (background timer)
//   • User clicks "Check for updates" in the UI

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_API_URL: &str =
    "https://api.github.com/repos/SepJs/aegis-guard/releases/latest";

/// Information about an available update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version:  String,
    pub release_url:     String,
    pub release_notes:   String,
    pub update_available: bool,
}

/// Minimal GitHub release API response shape.
#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    body:     Option<String>,
}

/// Check GitHub for a newer release.
/// Returns UpdateInfo regardless of whether an update is available.
pub async fn check_update() -> Result<UpdateInfo> {
    debug!("checking for update against GitHub API");

    let client = reqwest::Client::builder()
        .user_agent(format!("aegis-guard/{}", CURRENT_VERSION))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let release: GithubRelease = client
        .get(GITHUB_API_URL)
        .send()
        .await?
        .json()
        .await?;

    // Strip leading 'v' from tag if present
    let latest_raw = release.tag_name.trim_start_matches('v');
    let latest  = semver::Version::parse(latest_raw)?;
    let current = semver::Version::parse(CURRENT_VERSION)?;

    let update_available = latest > current;

    if update_available {
        info!(
            current = CURRENT_VERSION,
            latest  = %latest,
            "update available"
        );
    } else {
        debug!(version = CURRENT_VERSION, "already up to date");
    }

    Ok(UpdateInfo {
        current_version:  CURRENT_VERSION.into(),
        latest_version:   latest.to_string(),
        release_url:      release.html_url,
        release_notes:    release.body.unwrap_or_default(),
        update_available,
    })
}
