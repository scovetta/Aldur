//! Binary parsers for PE, ELF, Mach-O, PDB, and DWARF
//!
//! This crate provides parsers for various binary formats:
//! - PE (Portable Executable) for Windows binaries
//! - ELF (Executable and Linkable Format) for Linux/Unix binaries
//! - Mach-O for macOS/iOS binaries
//! - PDB for Windows debug symbols
//! - DWARF for Linux/Unix debug symbols

pub mod dwarf;
pub mod elf;
pub mod macho;
pub mod memory;
pub mod packer;
pub mod pdb;
pub mod pe;

pub use dwarf::DwarfInfo;
pub use elf::ElfBinary;
pub use macho::MachOBinary;
pub use memory::{
    BinaryData, MemoryBudget, MemoryBudgetExceeded, DEFAULT_HEAP_BUDGET, DEFAULT_MMAP_THRESHOLD,
};
pub use pdb::PdbFile;
pub use pe::PeBinary;

use aldur_core::{Binary, BinaryFormat};
use std::path::Path;

/// Detect the format of a binary file
pub fn detect_format(path: &Path) -> std::io::Result<BinaryFormat> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;

    // Check magic bytes
    match &magic {
        // PE: MZ magic
        [0x4D, 0x5A, ..] => Ok(BinaryFormat::PE),
        // ELF: 0x7F ELF
        [0x7F, 0x45, 0x4C, 0x46] => Ok(BinaryFormat::ELF),
        // Mach-O: various magic values
        [0xFE, 0xED, 0xFA, 0xCE] => Ok(BinaryFormat::MachO), // 32-bit
        [0xFE, 0xED, 0xFA, 0xCF] => Ok(BinaryFormat::MachO), // 64-bit
        [0xCE, 0xFA, 0xED, 0xFE] => Ok(BinaryFormat::MachO), // 32-bit reversed
        [0xCF, 0xFA, 0xED, 0xFE] => Ok(BinaryFormat::MachO), // 64-bit reversed
        [0xCA, 0xFE, 0xBA, 0xBE] => Ok(BinaryFormat::MachO), // Fat binary
        _ => Ok(BinaryFormat::Unknown),
    }
}

/// Load a binary from a path, automatically detecting the format
pub fn load_binary(path: &Path) -> aldur_core::Result<Box<dyn Binary>> {
    let format = detect_format(path).map_err(|e| {
        aldur_core::AldurError::binary_load(path.display().to_string(), e.to_string())
    })?;

    match format {
        BinaryFormat::PE => {
            let pe = PeBinary::load(path)?;
            Ok(Box::new(pe))
        }
        BinaryFormat::ELF => {
            let elf = ElfBinary::load(path)?;
            Ok(Box::new(elf))
        }
        BinaryFormat::MachO => {
            let macho = MachOBinary::load(path)?;
            Ok(Box::new(macho))
        }
        BinaryFormat::Unknown => Err(aldur_core::AldurError::InvalidFormat(
            path.display().to_string(),
        )),
    }
}

/// Check if a file can be loaded as a binary
pub fn can_load(path: &Path) -> bool {
    detect_format(path)
        .map(|f| f != BinaryFormat::Unknown)
        .unwrap_or(false)
}
