// threat-intel/src/lib.rs — Phase 5: CTI feed matching
//
// Matches observed IPs, domains, and file hashes against known threat
// intelligence feeds. Supports local offline feed + optional live update.
//
// Feeds supported:
//   • Offline bundled feed (JSON — ships with the binary)
//   • Abuse.ch URLhaus (malware URLs + IPs)
//   • Emerging Threats block list (IP ranges)
//   • Custom user-defined IOC list
//
// All matching is O(1) via pre-built HashSet/HashMaps.
// Feed updates run in background every 6 hours.

pub mod feed;
pub mod ioc;
pub mod matcher;
pub mod models;

pub use matcher::ThreatMatcher;
pub use models::{IocKind, IocMatch, ThreatEntry};
