// entropy/src/scan.rs — file/directory scanner using rayon thread pool

use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::Result;
use rayon::prelude::*;
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::{
    classify::{classify_entropy, build_note, guess_mime, shannon_entropy},
    models::{FileScanResult, RiskLevel, ScanRequest, ScanSummary},
};

/// Entry point — called from Tauri command.
/// Blocks the calling thread (run via spawn_blocking in Tauri).
pub fn scan_path(req: ScanRequest) -> Result<ScanSummary> {
    let started = Instant::now();
    let root    = Path::new(&req.path);

    // Collect file paths first
    let paths: Vec<_> = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        let walker = WalkDir::new(root)
            .max_depth(if req.recursive { usize::MAX } else { 1 })
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path());
        walker.collect()
    };

    let total_files = paths.len();

    // Scan in parallel using rayon
    let skipped  = Arc::new(Mutex::new(0usize));
    let skipped2 = skipped.clone();

    let mut results: Vec<FileScanResult> = paths
        .par_iter()
        .map(|path| {
            scan_file(path, req.max_bytes, &skipped2)
        })
        .collect();

    // Sort by entropy descending (highest risk first)
    results.sort_by(|a, b| {
        b.entropy.unwrap_or(0.0)
            .partial_cmp(&a.entropy.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let skipped_count = *skipped.lock().unwrap();
    let scanned_count = total_files - skipped_count;
    let high_risk     = results.iter().filter(|r| r.risk == RiskLevel::High).count();
    let medium_risk   = results.iter().filter(|r| r.risk == RiskLevel::Medium).count();

    Ok(ScanSummary {
        total_files,
        scanned_files: scanned_count,
        skipped_files: skipped_count,
        high_risk,
        medium_risk,
        results,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

/// Scan a single file — returns a FileScanResult.
fn scan_file(
    path:      &Path,
    max_bytes: u64,
    skipped:   &Arc<Mutex<usize>>,
) -> FileScanResult {
    let path_str = path.to_string_lossy().into_owned();

    // Stat the file
    let metadata = match fs::metadata(path) {
        Ok(m)  => m,
        Err(e) => {
            warn!("stat failed for {}: {e}", path.display());
            *skipped.lock().unwrap() += 1;
            return skip_result(path_str, 0, format!("stat error: {e}"));
        }
    };

    let size = metadata.len();

    // Skip files that are too large
    if size > max_bytes {
        debug!("skipping large file: {} ({} bytes)", path.display(), size);
        *skipped.lock().unwrap() += 1;
        return skip_result(
            path_str,
            size,
            format!("file too large ({} bytes > {} limit)", size, max_bytes),
        );
    }

    // Read file bytes
    let data = match fs::read(path) {
        Ok(d)  => d,
        Err(e) => {
            warn!("read failed for {}: {e}", path.display());
            *skipped.lock().unwrap() += 1;
            return skip_result(path_str, size, format!("read error: {e}"));
        }
    };

    // MIME guess from magic bytes
    let mime = guess_mime(&data[..data.len().min(16)]).to_string();

    // Entropy calculation
    let h    = shannon_entropy(&data);
    let risk = classify_entropy(h);
    let note = build_note(h, &risk, &mime);

    debug!(
        path = %path.display(),
        entropy = h,
        risk = %risk,
        "scanned"
    );

    FileScanResult {
        path: path_str,
        size_bytes: size,
        entropy: Some(h),
        risk,
        mime_guess: mime,
        note,
    }
}

fn skip_result(path: String, size: u64, reason: String) -> FileScanResult {
    FileScanResult {
        path,
        size_bytes: size,
        entropy:    None,
        risk:       RiskLevel::Skipped,
        mime_guess: "unknown".into(),
        note:       reason,
    }
}
