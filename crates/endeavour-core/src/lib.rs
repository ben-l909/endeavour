//! Core types and utilities for Endeavour binary analysis.
//!
//! This crate provides configuration management, session persistence, and domain models
//! for the Endeavour reverse engineering toolkit.

/// Configuration management for Endeavour.

pub mod config;
/// Core error types.
pub mod error;
/// Binary loading and parsing utilities.
pub mod loader;
/// Core domain models.
pub mod models;
/// SQLite-backed session persistence.
pub mod store;

pub use error::{Error, Result};
pub use models::*;
pub use store::CacheStats;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        Arch, Binary, Finding, FindingKind, ObjCClass, ObjCInfo, Section, Segment, Session, Symbol,
        SymbolKind,
    };

    #[test]
    fn binary_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let binary = Binary {
            uuid: uuid::Uuid::new_v4(),
            path: PathBuf::from("/tmp/demo.bin"),
            arch: Arch::Arm64,
            segments: vec![Segment {
                name: "__TEXT".to_string(),
                vmaddr: 0x1000,
                vmsize: 0x2000,
                fileoff: 0,
                filesize: 0x2000,
                sections: vec![Section {
                    name: "__text".to_string(),
                    addr: 0x1000,
                    size: 0x1000,
                }],
            }],
            symbols: vec![Symbol {
                name: "_main".to_string(),
                addr: 0x1000,
                kind: SymbolKind::Function,
            }],
            objc_metadata: Some(ObjCInfo {
                classes: vec![ObjCClass {
                    name: "AppDelegate".to_string(),
                    methods: vec!["applicationDidFinishLaunching:".to_string()],
                    superclass: Some("NSObject".to_string()),
                }],
                protocols: vec!["UIApplicationDelegate".to_string()],
                categories: vec!["AppDelegate(Category)".to_string()],
            }),
        };

        let encoded = serde_json::to_string(&binary)?;
        let decoded: Binary = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, binary);

        Ok(())
    }

    #[test]
    fn session_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let session = Session {
            id: uuid::Uuid::new_v4(),
            binary_id: uuid::Uuid::new_v4(),
            created_at: "2026-03-02T12:34:56Z".to_string(),
            name: "bootstrap-session".to_string(),
        };

        let encoded = serde_json::to_string(&session)?;
        let decoded: Session = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, session);

        Ok(())
    }

    #[test]
    fn finding_json_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let finding = Finding {
            pass_name: "mba-simplifier".to_string(),
            pass_version: 1,
            kind: FindingKind::MBASimplified,
            confidence: 0.97,
        };

        let encoded = serde_json::to_string(&finding)?;
        let decoded: Finding = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, finding);

        Ok(())
    }
}
