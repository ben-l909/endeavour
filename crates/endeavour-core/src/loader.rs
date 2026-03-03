use std::collections::BTreeSet;
use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};

use goblin::mach::constants::cputype;
use goblin::mach::{load_command::CommandVariant, symbols, Mach, MachO, SingleArch};
use memmap2::MmapOptions;

use crate::error::{Error, Result};
use crate::models::{Arch, Binary, ObjCClass, ObjCInfo, Section, Segment, Symbol, SymbolKind};

/// Load and parse a Mach-O binary from the given path.
pub fn load_binary(path: &Path) -> Result<Binary> {
    let file = File::open(path)?;
    // SAFETY: The file descriptor is opened read-only and the mapping is exposed
    // as an immutable byte slice. The map is owned by this function and cannot
    // outlive the Binary construction path that consumes it.
    let mmap = unsafe { MmapOptions::new().map(&file) }?;
    parse_macho(&mmap, path.to_path_buf())
}

/// Parse a Mach-O from raw bytes (for testing or in-memory use).
pub fn parse_macho(data: &[u8], path: PathBuf) -> Result<Binary> {
    let mach = Mach::parse(data).map_err(|e| Error::ParseError(e.to_string()))?;
    match mach {
        Mach::Binary(macho) => build_binary(&macho, path),
        Mach::Fat(fat) => {
            let selected_index = select_fat_index(&fat)?;
            let selected = fat
                .get(selected_index)
                .map_err(|e| Error::ParseError(e.to_string()))?;
            match selected {
                SingleArch::MachO(macho) => build_binary(&macho, path),
                _ => Err(Error::ParseError(
                    "selected fat slice is not a Mach-O binary".to_string(),
                )),
            }
        }
    }
}

fn build_binary(macho: &MachO<'_>, path: PathBuf) -> Result<Binary> {
    let arch = detect_arch(macho.header.cputype);
    let uuid = extract_uuid(macho);

    let mut segments_out = Vec::new();
    let mut section_names = Vec::new();
    let mut objc_sections = Vec::new();

    for segment in &macho.segments {
        let segment_name = segment
            .name()
            .map_err(|e| Error::ParseError(e.to_string()))?
            .to_string();

        let mut sections_out = Vec::new();
        for section in segment {
            let (section, section_data) = section.map_err(|e| Error::ParseError(e.to_string()))?;
            let section_name = section
                .name()
                .map_err(|e| Error::ParseError(e.to_string()))?
                .to_string();

            section_names.push(section_name.clone());
            if section_name.starts_with("__objc") {
                objc_sections.push((section_name.clone(), section_data.to_vec()));
            }

            sections_out.push(Section {
                name: section_name,
                addr: section.addr,
                size: section.size,
            });
        }

        segments_out.push(Segment {
            name: segment_name,
            vmaddr: segment.vmaddr,
            vmsize: segment.vmsize,
            fileoff: segment.fileoff,
            filesize: segment.filesize,
            sections: sections_out,
        });
    }

    let symbols = macho
        .symbols()
        .map(|entry| {
            let (name, nlist) = entry.map_err(|e| Error::ParseError(e.to_string()))?;
            let section_name = if nlist.n_sect > 0 {
                section_names.get(nlist.n_sect - 1).map(String::as_str)
            } else {
                None
            };

            Ok(Symbol {
                name: name.to_string(),
                addr: nlist.n_value,
                kind: classify_symbol(name, &nlist, section_name),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let objc_metadata = extract_objc_metadata(&objc_sections);

    Ok(Binary {
        uuid,
        path,
        arch,
        segments: segments_out,
        symbols,
        objc_metadata,
    })
}

fn select_fat_index(fat: &goblin::mach::MultiArch<'_>) -> Result<usize> {
    let host_cputype = host_cputype();
    let mut first_index = None;

    for (index, arch_res) in fat.iter_arches().enumerate() {
        let arch = arch_res.map_err(|e| Error::ParseError(e.to_string()))?;
        if first_index.is_none() {
            first_index = Some(index);
        }
        if let Some(host) = host_cputype {
            if arch.cputype == host {
                return Ok(index);
            }
        }
    }

    first_index
        .ok_or_else(|| Error::ParseError("fat binary contains no architecture slices".into()))
}

fn host_cputype() -> Option<u32> {
    match env::consts::ARCH {
        "aarch64" => Some(cputype::CPU_TYPE_ARM64),
        "x86_64" => Some(cputype::CPU_TYPE_X86_64),
        _ => None,
    }
}

fn detect_arch(cputype_raw: u32) -> Arch {
    match cputype_raw {
        cputype::CPU_TYPE_ARM64 | cputype::CPU_TYPE_ARM64_32 => Arch::Arm64,
        cputype::CPU_TYPE_X86_64 => Arch::X86_64,
        other => Arch::Unknown(format!("cputype_{other:#x}")),
    }
}

fn extract_uuid(macho: &MachO<'_>) -> uuid::Uuid {
    for load_command in &macho.load_commands {
        if let CommandVariant::Uuid(command) = load_command.command {
            return uuid::Uuid::from_bytes(command.uuid);
        }
    }

    uuid::Uuid::nil()
}

fn classify_symbol(name: &str, nlist: &symbols::Nlist, section_name: Option<&str>) -> SymbolKind {
    if name.contains("OBJC_CLASS_$_") || name.contains("OBJC_METACLASS_$_") {
        return SymbolKind::ObjCClass;
    }

    if name.starts_with("-[")
        || name.starts_with("+[")
        || name.contains("OBJC_METH_VAR_NAME_")
        || name.contains("objc_msgSend")
    {
        return SymbolKind::ObjCMethod;
    }

    if is_function_symbol(nlist, section_name) {
        return SymbolKind::Function;
    }

    if is_data_symbol(nlist, section_name) {
        return SymbolKind::Data;
    }

    SymbolKind::Other
}

fn is_function_symbol(nlist: &symbols::Nlist, section_name: Option<&str>) -> bool {
    let type_bits = nlist.n_type & symbols::N_TYPE;
    if type_bits != symbols::N_SECT {
        return false;
    }

    match section_name {
        Some("__text") | Some("__stubs") | Some("__auth_stubs") => true,
        Some(section) => section.starts_with("__text"),
        None => false,
    }
}

fn is_data_symbol(nlist: &symbols::Nlist, section_name: Option<&str>) -> bool {
    let type_bits = nlist.n_type & symbols::N_TYPE;
    if type_bits == symbols::N_ABS {
        return true;
    }

    if type_bits != symbols::N_SECT {
        return false;
    }

    !matches!(
        section_name,
        Some("__text") | Some("__stubs") | Some("__auth_stubs")
    )
}

fn extract_objc_metadata(objc_sections: &[(String, Vec<u8>)]) -> Option<ObjCInfo> {
    let mut class_names = BTreeSet::new();
    let mut method_names = BTreeSet::new();
    let mut protocols = BTreeSet::new();
    let mut categories = BTreeSet::new();

    for (section_name, data) in objc_sections {
        let strings = extract_cstrings(data, 2);

        if section_name.contains("classname") || section_name.contains("class") {
            for value in &strings {
                if looks_like_objc_identifier(value) {
                    class_names.insert(value.clone());
                }
            }
        }

        if section_name.contains("meth") {
            for value in &strings {
                if looks_like_method_name(value) {
                    method_names.insert(value.clone());
                }
            }
        }

        if section_name.contains("proto") {
            for value in &strings {
                if looks_like_objc_identifier(value) {
                    protocols.insert(value.clone());
                }
            }
        }

        if section_name.contains("cat") {
            for value in &strings {
                if looks_like_objc_identifier(value) {
                    categories.insert(value.clone());
                }
            }
        }
    }

    if class_names.is_empty()
        && method_names.is_empty()
        && protocols.is_empty()
        && categories.is_empty()
    {
        return None;
    }

    let mut classes: Vec<ObjCClass> = class_names
        .into_iter()
        .map(|name| ObjCClass {
            name,
            methods: Vec::new(),
            superclass: None,
        })
        .collect();

    let method_list: Vec<String> = method_names.into_iter().collect();
    if !method_list.is_empty() {
        if classes.is_empty() {
            classes.push(ObjCClass {
                name: "<unknown_objc_class>".to_string(),
                methods: method_list,
                superclass: None,
            });
        } else if let Some(first) = classes.first_mut() {
            first.methods = method_list;
        }
    }

    Some(ObjCInfo {
        classes,
        protocols: protocols.into_iter().collect(),
        categories: categories.into_iter().collect(),
    })
}

fn extract_cstrings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();

    for byte in data {
        if *byte == 0 {
            if current.len() >= min_len {
                if let Ok(text) = std::str::from_utf8(&current) {
                    let text = text.trim();
                    if !text.is_empty() {
                        out.push(text.to_string());
                    }
                }
            }
            current.clear();
            continue;
        }

        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(*byte);
        } else {
            current.clear();
        }
    }

    out
}

fn looks_like_objc_identifier(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'.')
}

fn looks_like_method_name(value: &str) -> bool {
    value.contains(':')
        || value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::parse_macho;
    use crate::models::Arch;

    #[test]
    fn parse_minimal_macho_header_arm64() {
        let bytes = macho64_header(0x0100_000c);
        let binary = parse_macho(&bytes, PathBuf::from("/tmp/min-arm64")).unwrap();
        assert_eq!(binary.arch, Arch::Arm64);
        assert_eq!(binary.segments.len(), 0);
    }

    #[test]
    fn parse_minimal_macho_header_x86_64() {
        let bytes = macho64_header(0x0100_0007);
        let binary = parse_macho(&bytes, PathBuf::from("/tmp/min-x64")).unwrap();
        assert_eq!(binary.arch, Arch::X86_64);
    }

    #[test]
    fn parse_macho_unknown_arch() {
        let bytes = macho64_header(0x1234_5678);
        let binary = parse_macho(&bytes, PathBuf::from("/tmp/min-unknown")).unwrap();
        assert!(matches!(binary.arch, Arch::Unknown(_)));
    }

    #[test]
    fn parse_invalid_data_errors() {
        let err = parse_macho(&[0x00, 0x01, 0x02], PathBuf::from("/tmp/invalid")).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("parse") || message.contains("Failed to parse"));
    }

    fn macho64_header(cputype: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
        out.extend_from_slice(&cputype.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }
}
