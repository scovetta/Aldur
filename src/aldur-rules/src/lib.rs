//! Security rules for Aldur
//!
//! This crate contains all the security rules that analyze binaries.
//! Rules are organized by binary format:
//! - PE rules (Windows binaries)
//! - ELF rules (Linux/Unix binaries)
//! - Mach-O rules (macOS/iOS binaries)

pub mod elf;
pub mod macho;
pub mod pe;
pub mod rule_ids;

#[cfg(test)]
pub mod test_utils;

pub use rule_ids::*;

use aldur_core::Rule;

/// Get all available rules
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();

    // PE rules
    rules.extend(pe::all_rules());

    // ELF rules
    rules.extend(elf::all_rules());

    // Mach-O rules
    rules.extend(macho::all_rules());

    rules
}

/// Get rules by binary format
pub fn rules_for_pe() -> Vec<Box<dyn Rule>> {
    pe::all_rules()
}

pub fn rules_for_elf() -> Vec<Box<dyn Rule>> {
    elf::all_rules()
}

pub fn rules_for_macho() -> Vec<Box<dyn Rule>> {
    macho::all_rules()
}
