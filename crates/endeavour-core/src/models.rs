use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Represents a parsed Mach-O binary and extracted metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Binary {
    /// The Mach-O LC_UUID value.
    pub uuid: uuid::Uuid,
    /// The original filesystem path of the binary.
    pub path: PathBuf,
    /// The detected architecture.
    pub arch: Arch,
    /// The loadable segments contained in the binary.
    pub segments: Vec<Segment>,
    /// Symbols recovered from the binary.
    pub symbols: Vec<Symbol>,
    /// Optional Objective-C metadata, when present.
    pub objc_metadata: Option<ObjCInfo>,
}

/// CPU architecture of the binary payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Arch {
    /// ARM64 architecture.
    Arm64,
    /// x86_64 architecture.
    X86_64,
    /// Any unsupported or unknown architecture string.
    Unknown(String),
}

/// Mach-O segment with virtual and file mappings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Segment {
    /// Segment name.
    pub name: String,
    /// Virtual memory address.
    pub vmaddr: u64,
    /// Virtual memory size.
    pub vmsize: u64,
    /// File offset of segment data.
    pub fileoff: u64,
    /// File size of segment data.
    pub filesize: u64,
    /// Sections belonging to the segment.
    pub sections: Vec<Section>,
}

/// Mach-O section descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Section {
    /// Section name.
    pub name: String,
    /// Runtime address.
    pub addr: u64,
    /// Section size in bytes.
    pub size: u64,
}

/// Symbol record extracted from static metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Symbol {
    /// Symbol name.
    pub name: String,
    /// Relative virtual address (RVA).
    pub addr: u64,
    /// Symbol classification.
    pub kind: SymbolKind,
}

/// Symbol classification used by analysis passes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SymbolKind {
    /// Executable function.
    Function,
    /// Data object.
    Data,
    /// Objective-C class symbol.
    ObjCClass,
    /// Objective-C method symbol.
    ObjCMethod,
    /// Any unclassified symbol.
    Other,
}

/// Objective-C metadata extracted from Mach-O sections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjCInfo {
    /// Objective-C classes.
    pub classes: Vec<ObjCClass>,
    /// Objective-C protocol names.
    pub protocols: Vec<String>,
    /// Objective-C category names.
    pub categories: Vec<String>,
}

/// Objective-C class metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjCClass {
    /// Class name.
    pub name: String,
    /// Method names belonging to this class.
    pub methods: Vec<String>,
    /// Optional superclass name.
    pub superclass: Option<String>,
}

/// Function-level metadata tracked by the system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Function {
    /// Identifier of the source binary.
    pub binary_id: uuid::Uuid,
    /// Relative virtual address of the function.
    pub rva: u64,
    /// Function display name.
    pub name: String,
    /// Optional recovered function signature.
    pub signature: Option<String>,
}

/// A pass-generated finding attached to the analysis session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Name of the producing pass.
    pub pass_name: String,
    /// Version of the producing pass.
    pub pass_version: u64,
    /// Finding classification.
    pub kind: FindingKind,
    /// Confidence score from 0.0 to 1.0.
    pub confidence: f64,
}

/// The semantic type of an analysis finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingKind {
    /// Rename recommendation.
    Rename,
    /// Type correction recommendation.
    TypeChange,
    /// Comment recommendation.
    Comment,
    /// MBA expression simplification result.
    MBASimplified,
    /// Algorithm identification result.
    AlgorithmIdentified,
    /// Any unmodeled finding type.
    Other(String),
}

/// A named analysis session bound to a binary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    /// Session identifier.
    pub id: uuid::Uuid,
    /// Identifier of the analyzed binary.
    pub binary_id: uuid::Uuid,
    /// Session creation timestamp as an RFC3339 string.
    pub created_at: String,
    /// Human-readable session name.
    pub name: String,
}
