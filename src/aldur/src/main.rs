//! Aldur binary security analyzer CLI

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;

mod analyze;
mod archive;
mod baseline;
mod config;
mod custom_profiles;
mod output;
mod profiles;
mod summary;

use analyze::AnalyzeCommand;

/// Aldur - Binary security analyzer
///
/// Analyzes PE, ELF, and Mach-O binaries for security vulnerabilities.
#[derive(Parser)]
#[command(name = "aldur")]
#[command(author = "Michael Scovetta")]
#[command(version)]
#[command(about = "Binary security analyzer for PE, ELF, and Mach-O binaries")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze binary files for security issues
    Analyze(AnalyzeArgs),

    /// Export rules metadata
    ExportRules(ExportRulesArgs),

    /// Export configuration
    ExportConfig(ExportConfigArgs),

    /// Dump binary information
    Dump(DumpArgs),

    /// List available security profiles
    ListProfiles,
}

/// Arguments for the analyze command
#[derive(Parser)]
pub struct AnalyzeArgs {
    /// Files, directories, or glob patterns to analyze
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Output file path for SARIF results
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Output format: text (default), text-color, sarif, github-actions (or gha)
    #[arg(short = 'F', long, default_value = "text")]
    pub format: String,

    /// Show passing rules in text output
    #[arg(long, default_value = "false")]
    pub show_passed: bool,

    /// Recurse into subdirectories
    #[arg(short, long, default_value = "false")]
    pub recurse: bool,

    /// Path to configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Suppress console output
    #[arg(short, long, default_value = "false")]
    pub quiet: bool,

    /// Generate timing statistics
    #[arg(short, long, default_value = "false")]
    pub statistics: bool,

    /// Symbol path for PDB lookup (Windows)
    #[arg(long)]
    pub sympath: Option<String>,

    /// Local symbol directories
    #[arg(long)]
    pub local_symbol_directories: Option<String>,

    /// Use rich return code
    #[arg(long, default_value = "false")]
    pub rich_return_code: bool,

    /// Failure levels to include (Error, Warning, Note)
    #[arg(long)]
    pub level: Option<String>,

    /// Result kinds to include
    #[arg(long)]
    pub kind: Option<String>,

    /// Baseline SARIF file for comparison (suppress known issues)
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Save current results as a new baseline file
    #[arg(long)]
    pub save_baseline: Option<PathBuf>,

    /// Security profile: default, strict, relaxed, android, rhel, fips (or custom profile name)
    #[arg(short = 'P', long, default_value = "default")]
    pub profile: String,

    /// Path to custom profiles file (enables custom profile names with --profile)
    #[arg(long)]
    pub custom_profiles: Option<PathBuf>,

    /// Include specific rules (comma-separated rule IDs), overriding profile exclusions
    #[arg(long, value_delimiter = ',')]
    pub include: Vec<String>,

    /// Exclude specific rules (comma-separated rule IDs), overriding profile inclusions
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Show multi-target summary report (when scanning multiple binaries)
    #[arg(long, default_value = "false")]
    pub summary: bool,

    /// Output summary as markdown (for GitHub step summary)
    #[arg(long, default_value = "false")]
    pub summary_markdown: bool,

    /// Maximum file size in kilobytes (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub max_file_size_kb: u64,

    /// Ignore PDB load errors
    #[arg(long, default_value = "false")]
    pub ignore_pdb_load_error: bool,

    /// Number of threads for parallel analysis (0 = auto)
    #[arg(long, default_value = "0")]
    pub threads: usize,

    /// Only show new issues when using baseline (hide existing issues)
    #[arg(long, default_value = "false")]
    pub new_only: bool,

    /// Scan contents of archive files (zip, tar, 7z, etc.)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub scan_archives: bool,

    /// Scan nested archives within archives
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub scan_nested_archives: bool,

    /// Maximum archive extraction depth
    #[arg(long, default_value = "3")]
    pub max_archive_depth: usize,

    /// Maximum uncompressed size for archive extraction in MB (0 = unlimited)
    #[arg(long, default_value = "10240")]
    pub max_archive_size_mb: u64,

    /// Maximum number of entries to extract from an archive (0 = unlimited)
    #[arg(long, default_value = "100000")]
    pub max_archive_entries: usize,

    /// Include object files (.o) in analysis (usually not needed)
    #[arg(long, default_value = "false")]
    pub include_object_files: bool,
}

/// Arguments for export-rules command
#[derive(Parser)]
pub struct ExportRulesArgs {
    /// Output file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Output format (json, markdown)
    #[arg(long, default_value = "json")]
    pub format: String,
}

/// Arguments for export-config command
#[derive(Parser)]
pub struct ExportConfigArgs {
    /// Output file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Arguments for dump command
#[derive(Parser)]
pub struct DumpArgs {
    /// Binary file to dump
    #[arg(required = true)]
    pub file: PathBuf,

    /// Include section details
    #[arg(long, default_value = "false")]
    pub sections: bool,

    /// Include import details
    #[arg(long, default_value = "false")]
    pub imports: bool,

    /// Include export details
    #[arg(long, default_value = "false")]
    pub exports: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(if cli.verbose {
                    tracing::Level::DEBUG.into()
                } else {
                    tracing::Level::INFO.into()
                }),
        )
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set up logging")?;

    let result = match cli.command {
        Commands::Analyze(args) => {
            let cmd = AnalyzeCommand::new(args);
            cmd.run()
        }
        Commands::ExportRules(args) => export_rules(args),
        Commands::ExportConfig(args) => export_config(args),
        Commands::Dump(args) => dump_binary(args),
        Commands::ListProfiles => list_profiles(),
    };

    result
}

fn list_profiles() -> Result<()> {
    println!("Available security profiles:\n");
    for (name, description) in profiles::list_profiles() {
        println!("  {:<12} {}", name, description);
    }
    println!("\nUsage: aldur analyze --profile <name> <targets>");
    Ok(())
}

fn export_rules(args: ExportRulesArgs) -> Result<()> {
    let rules = aldur_rules::all_rules();

    let output: Vec<serde_json::Value> = rules
        .iter()
        .map(|rule| {
            let desc = rule.descriptor();
            serde_json::json!({
                "id": desc.id,
                "name": desc.name,
                "shortDescription": desc.short_description,
                "fullDescription": desc.full_description,
                "helpUri": desc.help_uri,
                "defaultLevel": format!("{:?}", desc.default_level),
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&output)?;

    if let Some(path) = args.output {
        std::fs::write(&path, &json)?;
        info!("Rules exported to {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(())
}

fn export_config(_args: ExportConfigArgs) -> Result<()> {
    let rules = aldur_rules::all_rules();

    let config: serde_json::Value = serde_json::json!({
        "rules": rules.iter().map(|r| {
            serde_json::json!({
                "id": r.descriptor().id,
                "enabled": true,
                "level": format!("{:?}", r.descriptor().default_level),
            })
        }).collect::<Vec<_>>()
    });

    let json = serde_json::to_string_pretty(&config)?;
    println!("{}", json);

    Ok(())
}

fn dump_binary(args: DumpArgs) -> Result<()> {
    let path = &args.file;

    if !path.exists() {
        anyhow::bail!("File not found: {}", path.display());
    }

    let binary = aldur_parsers::load_binary(path)
        .context("Failed to load binary")?;

    println!("File: {}", path.display());
    println!("Format: {}", binary.format());
    println!("Type: {}", binary.binary_type());
    println!("64-bit: {}", binary.is_64_bit());
    println!("Valid: {}", binary.is_valid());

    if let Some(error) = binary.load_error() {
        println!("Load Error: {}", error);
    }

    // Format-specific details
    match binary.format() {
        aldur_core::BinaryFormat::PE => {
            if let Some(pe) = binary.as_any().downcast_ref::<aldur_parsers::PeBinary>() {
                println!("\nPE Details:");
                println!("  Image Base: 0x{:016x}", pe.image_base);
                println!("  Entry Point: 0x{:08x}", pe.entry_point);
                println!("  Linker Version: {}.{}", pe.linker_version_major, pe.linker_version_minor);
                println!("  DYNAMICBASE: {}", pe.is_dynamic_base());
                println!("  HIGH_ENTROPY_VA: {}", pe.is_high_entropy_va());
                println!("  NX_COMPAT: {}", pe.is_nx_compat());
                println!("  GUARD_CF: {}", pe.has_guard_cf());
                println!("  FORCE_INTEGRITY: {}", pe.has_force_integrity());

                if args.sections {
                    println!("\nSections:");
                    for section in &pe.sections {
                        println!("  {} - VA: 0x{:08x}, Size: {}, Chars: 0x{:08x}",
                            section.name, section.virtual_address, section.virtual_size, section.characteristics);
                    }
                }
            }
        }
        aldur_core::BinaryFormat::ELF => {
            if let Some(elf) = binary.as_any().downcast_ref::<aldur_parsers::ElfBinary>() {
                println!("\nELF Details:");
                println!("  Type: {:?}", elf.elf_type);
                println!("  Entry Point: 0x{:016x}", elf.entry_point);
                println!("  PIE: {}", elf.is_pie());
                println!("  RELRO: {}", elf.has_relro);
                println!("  BIND_NOW: {}", elf.has_bind_now);
                println!("  GNU_STACK: {}", elf.has_gnu_stack);
                println!("  Executable Stack: {}", elf.has_executable_stack());
            }
        }
        aldur_core::BinaryFormat::MachO => {
            if let Some(macho) = binary.as_any().downcast_ref::<aldur_parsers::MachOBinary>() {
                println!("\nMach-O Details:");
                println!("  Fat Binary: {}", macho.is_fat);
                println!("  PIE: {}", macho.is_pie());
                println!("  Allows Stack Execution: {}", macho.allows_stack_execution());
                println!("  Architectures: {}", macho.architectures.len());
                for (i, arch) in macho.architectures.iter().enumerate() {
                    println!("    [{}] Type: {:?}, 64-bit: {}, PIE: {}",
                        i, arch.file_type, arch.is_64_bit, arch.is_pie());
                }
            }
        }
        _ => {}
    }

    Ok(())
}
