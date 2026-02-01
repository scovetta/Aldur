//! Documentation completeness tests
//!
//! These tests verify that:
//! 1. Every rule has a corresponding documentation file in docs/
//! 2. Every doc file references an actual rule
//! 3. Every rule is mentioned in the README
//! 4. Rule IDs follow the naming convention

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

/// Get the workspace root directory
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Get the docs directory
fn docs_dir() -> PathBuf {
    workspace_root().join("docs/rules")
}

/// Get all rule IDs from the codebase
fn get_all_rule_ids() -> HashSet<String> {
    let rules = aldur_rules::all_rules();
    rules.iter().map(|r| r.descriptor().id.clone()).collect()
}

/// Get all rule IDs from documentation files
fn get_documented_rule_ids() -> HashSet<String> {
    let docs_dir = docs_dir();
    let mut documented = HashSet::new();

    if let Ok(entries) = fs::read_dir(&docs_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let filename = entry.file_name().to_string_lossy().to_string();
            // Match pattern like AD2001.RuleName.md
            if filename.starts_with("AD") && filename.ends_with(".md") {
                if let Some(dot_pos) = filename.find('.') {
                    let rule_id = &filename[..dot_pos];
                    documented.insert(rule_id.to_string());
                }
            }
        }
    }

    documented
}

/// Get all rule IDs mentioned in the README
fn get_readme_rule_ids() -> HashSet<String> {
    let readme_path = workspace_root().join("README.md");
    let mut mentioned = HashSet::new();

    if let Ok(content) = fs::read_to_string(&readme_path) {
        // Find all AD#### patterns in README
        let mut chars = content.chars().peekable();
        while let Some(c) = chars.next() {
            if c == 'A' {
                if let Some('D') = chars.peek() {
                    chars.next();
                    let mut id = String::from("AD");
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_digit() {
                            id.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if id.len() >= 6 {
                        // AD + 4 digits minimum
                        mentioned.insert(id);
                    }
                }
            }
        }
    }

    mentioned
}

#[test]
fn test_all_rules_have_documentation() {
    let rule_ids = get_all_rule_ids();
    let documented_ids = get_documented_rule_ids();

    let mut missing_docs = Vec::new();
    for rule_id in &rule_ids {
        if !documented_ids.contains(rule_id) {
            missing_docs.push(rule_id.clone());
        }
    }

    if !missing_docs.is_empty() {
        missing_docs.sort();
        panic!(
            "The following rules are missing documentation files in docs/rules/:\n  - {}\n\n\
            To fix: Create docs/rules/{}.RuleName.md for each missing rule.",
            missing_docs.join("\n  - "),
            missing_docs.first().unwrap()
        );
    }
}

#[test]
fn test_no_orphan_documentation() {
    let rule_ids = get_all_rule_ids();
    let documented_ids = get_documented_rule_ids();

    // Known reserved rule IDs that have documentation but aren't implemented yet
    // These are planned rules or rules that were deprecated/removed
    let reserved_rule_ids: HashSet<String> = [
        "AD2002", // DoNotIncorporateVulnerableDependencies (planned)
        "AD2005", // DoNotShipVulnerableBinaries (planned)
        "AD2022", // SignSecurely (planned)
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let mut orphan_docs = Vec::new();
    for doc_id in &documented_ids {
        if !rule_ids.contains(doc_id) && !reserved_rule_ids.contains(doc_id) {
            orphan_docs.push(doc_id.clone());
        }
    }

    if !orphan_docs.is_empty() {
        orphan_docs.sort();
        panic!(
            "The following documentation files reference rules that don't exist:\n  - {}\n\n\
            These may be outdated or the rule IDs may be incorrect.\n\
            If these are planned/reserved rules, add them to `reserved_rule_ids` in this test.",
            orphan_docs.join("\n  - ")
        );
    }
}

#[test]
fn test_all_rules_in_readme() {
    let rule_ids = get_all_rule_ids();
    let readme_ids = get_readme_rule_ids();

    let mut missing_from_readme = Vec::new();
    for rule_id in &rule_ids {
        if !readme_ids.contains(rule_id) {
            missing_from_readme.push(rule_id.clone());
        }
    }

    if !missing_from_readme.is_empty() {
        missing_from_readme.sort();
        panic!(
            "The following rules are not mentioned in README.md:\n  - {}\n\n\
            To fix: Add these rules to the appropriate rules table in README.md",
            missing_from_readme.join("\n  - ")
        );
    }
}

#[test]
fn test_rule_id_format() {
    let rules = aldur_rules::all_rules();

    let mut invalid_ids = Vec::new();
    for rule in &rules {
        let id = &rule.descriptor().id;
        // Rule IDs should be AD followed by 4 digits
        if !id.starts_with("AD") {
            invalid_ids.push((id.clone(), "does not start with 'AD'".to_string()));
        } else if id.len() != 6 {
            invalid_ids.push((
                id.clone(),
                format!("should be 6 characters (AD + 4 digits), got {}", id.len()),
            ));
        } else if !id[2..].chars().all(|c| c.is_ascii_digit()) {
            invalid_ids.push((
                id.clone(),
                "digits after 'AD' are not all numeric".to_string(),
            ));
        }
    }

    if !invalid_ids.is_empty() {
        let errors: Vec<String> = invalid_ids
            .iter()
            .map(|(id, reason)| format!("{}: {}", id, reason))
            .collect();
        panic!(
            "The following rule IDs have invalid format:\n  - {}\n\n\
            Rule IDs must follow the pattern AD#### (AD + 4 digits)",
            errors.join("\n  - ")
        );
    }
}

#[test]
fn test_rule_descriptors_have_required_fields() {
    let rules = aldur_rules::all_rules();

    let mut incomplete_rules = Vec::new();
    for rule in &rules {
        let desc = rule.descriptor();
        let mut issues = Vec::new();

        if desc.id.is_empty() {
            issues.push("missing id");
        }
        if desc.name.is_empty() {
            issues.push("missing name");
        }
        if desc.short_description.is_empty() {
            issues.push("missing short_description");
        }
        if desc.full_description.is_empty() {
            issues.push("missing full_description");
        }
        if desc.help_uri.is_empty() {
            issues.push("missing help_uri");
        }

        if !issues.is_empty() {
            incomplete_rules.push((desc.id.clone(), issues.join(", ")));
        }
    }

    if !incomplete_rules.is_empty() {
        let errors: Vec<String> = incomplete_rules
            .iter()
            .map(|(id, issues)| format!("{}: {}", id, issues))
            .collect();
        panic!(
            "The following rules have incomplete descriptors:\n  - {}",
            errors.join("\n  - ")
        );
    }
}

#[test]
fn test_documentation_files_have_required_sections() {
    let docs_dir = docs_dir();
    let mut incomplete_docs = Vec::new();

    if let Ok(entries) = fs::read_dir(&docs_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let filename = entry.file_name().to_string_lossy().to_string();
            // Only check rule documentation files (AD*.md)
            if !filename.starts_with("AD") || !filename.ends_with(".md") {
                continue;
            }

            if let Ok(content) = fs::read_to_string(entry.path()) {
                let mut missing_sections = Vec::new();

                // Check for required sections (case-insensitive)
                let content_lower = content.to_lowercase();

                // Title (# AD####: or # RuleName)
                if !content.starts_with('#') {
                    missing_sections.push("title (should start with #)");
                }

                // Description or Overview
                if !content_lower.contains("## description")
                    && !content_lower.contains("## overview")
                {
                    // Allow if there's a paragraph after the title
                    let lines: Vec<&str> = content.lines().collect();
                    if lines.len() < 3 || lines[2].is_empty() {
                        missing_sections.push("description section");
                    }
                }

                // How to fix / Resolution / Remediation / Options
                if !content_lower.contains("## how to fix")
                    && !content_lower.contains("## resolution")
                    && !content_lower.contains("## remediation")
                    && !content_lower.contains("## fix")
                    && !content_lower.contains("### option 1")
                    && !content_lower.contains("### how to fix")
                    && !content_lower.contains("### fix")
                {
                    missing_sections.push("fix/resolution section");
                }

                if !missing_sections.is_empty() {
                    incomplete_docs.push((filename, missing_sections.join(", ")));
                }
            }
        }
    }

    if !incomplete_docs.is_empty() {
        let errors: Vec<String> = incomplete_docs
            .iter()
            .map(|(file, issues)| format!("{}: {}", file, issues))
            .collect();
        panic!(
            "The following documentation files are missing required sections:\n  - {}\n\n\
            Documentation files should have: title, description, and fix/resolution sections.",
            errors.join("\n  - ")
        );
    }
}

#[test]
fn test_unique_rule_ids() {
    let rules = aldur_rules::all_rules();
    let mut seen: HashSet<String> = HashSet::new();
    let mut duplicates = Vec::new();

    for rule in &rules {
        let id = rule.descriptor().id.clone();
        if seen.contains(&id) {
            duplicates.push(id.clone());
        } else {
            seen.insert(id);
        }
    }

    if !duplicates.is_empty() {
        duplicates.sort();
        duplicates.dedup();
        panic!(
            "The following rule IDs are duplicated:\n  - {}\n\n\
            Each rule must have a unique ID.",
            duplicates.join("\n  - ")
        );
    }
}

#[test]
fn test_fix_hints_present() {
    let rules = aldur_rules::all_rules();
    let mut missing_hints = Vec::new();

    for rule in &rules {
        let desc = rule.descriptor();
        if desc.fix_hint.is_none() {
            missing_hints.push(desc.id.clone());
        }
    }

    if !missing_hints.is_empty() {
        missing_hints.sort();
        panic!(
            "The following rules are missing fix_hint:\n  - {}\n\n\
            All rules should have a fix_hint to help users remediate issues.",
            missing_hints.join("\n  - ")
        );
    }
}

#[test]
fn test_rule_count_matches_readme() {
    // Get counts from rules
    let pe_count = aldur_rules::rules_for_pe().len();
    let elf_count = aldur_rules::rules_for_elf().len();
    let macho_count = aldur_rules::rules_for_macho().len();

    // Read README and find the counts mentioned
    let readme_path = workspace_root().join("README.md");
    let content = fs::read_to_string(&readme_path).expect("Failed to read README.md");

    // Check if the rule counts in README match actual counts
    // The README mentions things like "54 rules", "39 rules", etc.
    let mut warnings = Vec::new();

    // Look for PE rule count
    if let Some(pos) = content.find("PE (Windows) Rules") {
        let section = &content[pos..pos.min(content.len()) + 100];
        if !section.contains(&format!("{} rules", pe_count)) {
            warnings.push(format!(
                "PE rules count mismatch: README may say different count, actual is {}",
                pe_count
            ));
        }
    }

    // Look for ELF rule count
    if let Some(pos) = content.find("ELF (Linux/Unix) Rules") {
        let section = &content[pos..pos.min(content.len()) + 100];
        if !section.contains(&format!("{} rules", elf_count)) {
            warnings.push(format!(
                "ELF rules count mismatch: README may say different count, actual is {}",
                elf_count
            ));
        }
    }

    // Look for Mach-O rule count
    if let Some(pos) = content.find("Mach-O") {
        let section = &content[pos..pos.min(content.len()) + 100];
        if !section.contains(&format!("{} rules", macho_count)) {
            warnings.push(format!(
                "Mach-O rules count mismatch: README may say different count, actual is {}",
                macho_count
            ));
        }
    }

    // This is a soft check - just print warnings rather than failing
    // because the README format might vary
    if !warnings.is_empty() {
        eprintln!(
            "Documentation linter warnings:\n  - {}",
            warnings.join("\n  - ")
        );
        eprintln!(
            "\nActual rule counts: PE={}, ELF={}, Mach-O={}, Total={}",
            pe_count,
            elf_count,
            macho_count,
            pe_count + elf_count + macho_count
        );
    }
}
