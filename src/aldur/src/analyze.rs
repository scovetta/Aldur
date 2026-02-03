//! Analyze command implementation

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

use aldur_core::{AnalysisConfig, AnalysisContext, AnalysisResult, Rule, RuleDescriptor};
use aldur_sarif::SarifLogger;

use crate::AnalyzeArgs;
use crate::archive::{ArchiveConfig, ArchiveExtractor, ExtractedBinary};
use crate::baseline::{Baseline, BaselineComparison};
use crate::custom_profiles::CustomProfileRegistry;
use crate::output::{GitHubActionsFormatter, OutputFormat, TextFormatter};
use crate::profiles;
use crate::summary::MultiTargetSummary;

/// Represents a file to analyze, either directly from disk or extracted from an archive
struct AnalysisTarget {
    /// Path to the file on disk (may be in temp directory)
    pub path: PathBuf,
    /// Display name for the file (includes archive path if extracted)
    pub display_name: String,
    /// Original archive path if this file was extracted
    pub archive_source: Option<PathBuf>,
}

pub struct AnalyzeCommand {
    args: AnalyzeArgs,
    archive_config: ArchiveConfig,
}

impl AnalyzeCommand {
    pub fn new(args: AnalyzeArgs) -> Self {
        let archive_config = ArchiveConfig {
            max_uncompressed_size: args.max_archive_size_mb * 1024 * 1024,
            max_entries: args.max_archive_entries,
            max_depth: args.max_archive_depth,
            scan_nested: args.scan_nested_archives,
        };
        Self {
            args,
            archive_config,
        }
    }

    pub fn run(&self) -> Result<()> {
        let start_time = Instant::now();

        // Load custom profiles if specified
        let custom_registry = if let Some(ref custom_path) = self.args.custom_profiles {
            let registry = CustomProfileRegistry::load_from_file(custom_path)?;
            if !self.args.quiet {
                info!(
                    "Loaded {} custom profile(s) from {}",
                    registry.names().len(),
                    custom_path.display()
                );
            }
            Some(registry)
        } else {
            None
        };

        // Determine profile type: custom or built-in
        let (profile_name, custom_profile, builtin_profile) = {
            // First check custom profiles
            if let Some(ref registry) = custom_registry {
                if let Some(custom) = registry.get(&self.args.profile) {
                    (
                        custom.name.clone(),
                        Some(custom.clone()),
                        custom.get_base_profile(),
                    )
                } else if let Some(builtin) = profiles::get_profile(&self.args.profile) {
                    (builtin.name.clone(), None, Some(builtin))
                } else {
                    let available: Vec<_> = profiles::PROFILE_NAMES
                        .iter()
                        .map(|s| s.to_string())
                        .chain(registry.names().iter().map(|s| s.to_string()))
                        .collect();
                    anyhow::bail!(
                        "Unknown profile '{}'. Available profiles: {}",
                        self.args.profile,
                        available.join(", ")
                    );
                }
            } else if let Some(builtin) = profiles::get_profile(&self.args.profile) {
                (builtin.name.clone(), None, Some(builtin))
            } else {
                anyhow::bail!(
                    "Unknown profile '{}'. Available profiles: {}",
                    self.args.profile,
                    profiles::PROFILE_NAMES.join(", ")
                );
            }
        };

        if !self.args.quiet && self.args.profile != "default" {
            if let Some(ref custom) = custom_profile {
                let base_info = custom
                    .base_profile
                    .as_ref()
                    .map(|b| format!(" (based on {})", b))
                    .unwrap_or_default();
                info!("Using custom profile: {}{}", profile_name, base_info);
            } else if let Some(ref builtin) = builtin_profile {
                info!(
                    "Using security profile: {} - {}",
                    builtin.name, builtin.description
                );
            }
        }

        // Load baseline if specified
        let baseline = if let Some(ref baseline_path) = self.args.baseline {
            match Baseline::load(baseline_path) {
                Ok(b) => {
                    if !self.args.quiet {
                        info!(
                            "Loaded baseline from {} ({} known issues)",
                            baseline_path.display(),
                            b.known_issues.len()
                        );
                    }
                    Some(b)
                }
                Err(e) => {
                    warn!("Failed to load baseline: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Collect target files with a spinner for large directories
        let spinner = if !self.args.quiet && std::io::stderr().is_terminal() {
            let sp = ProgressBar::new_spinner();
            sp.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.cyan} {msg}")
                    .unwrap(),
            );
            sp.set_message("Discovering files...");
            sp.enable_steady_tick(std::time::Duration::from_millis(100));
            Some(sp)
        } else {
            None
        };

        let (files, _temp_dirs) = self.collect_files(spinner.as_ref())?;

        if let Some(sp) = spinner {
            sp.finish_and_clear();
        }

        if files.is_empty() {
            if !self.args.quiet {
                eprintln!("No valid analysis targets found.");
            }
            return Ok(());
        }

        // Count archive-extracted files
        let archive_file_count = files.iter().filter(|f| f.archive_source.is_some()).count();
        if !self.args.quiet {
            if archive_file_count > 0 {
                info!(
                    "Found {} files to analyze ({} from archives)",
                    files.len(),
                    archive_file_count
                );
            } else {
                info!("Found {} files to analyze", files.len());
            }
        }

        // Configure thread pool
        if self.args.threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(self.args.threads)
                .build_global()
                .ok();
        }

        // Get and filter rules based on profile, then apply --include and --exclude overrides
        let all_rules = aldur_rules::all_rules();

        // Convert include/exclude lists to sets for efficient lookup
        let include_set: std::collections::HashSet<_> =
            self.args.include.iter().map(|s| s.to_uppercase()).collect();
        let exclude_set: std::collections::HashSet<_> =
            self.args.exclude.iter().map(|s| s.to_uppercase()).collect();

        // Create a rule matcher closure that handles both custom and builtin profiles
        let matches_profile = |descriptor: &RuleDescriptor| -> bool {
            if let Some(ref custom) = custom_profile {
                custom.matches_rule(descriptor)
            } else if let Some(ref builtin) = builtin_profile {
                builtin.matches_rule(descriptor)
            } else {
                true // No profile means include all
            }
        };

        let rules: Vec<_> = all_rules
            .into_iter()
            .filter(|r| {
                let rule_id = r.id().to_uppercase();

                // If rule is explicitly excluded, skip it
                if exclude_set.contains(&rule_id) {
                    return false;
                }

                // If rule is explicitly included, include it regardless of profile
                if include_set.contains(&rule_id) {
                    return true;
                }

                // Otherwise, use profile filtering
                matches_profile(r.descriptor())
            })
            .collect();

        if !self.args.quiet {
            let mut info_msg = format!("Loaded {} rules (profile: {})", rules.len(), profile_name);
            if !self.args.include.is_empty() {
                info_msg.push_str(&format!(", +{} included", self.args.include.len()));
            }
            if !self.args.exclude.is_empty() {
                info_msg.push_str(&format!(", -{} excluded", self.args.exclude.len()));
            }
            info!("{}", info_msg);
        }

        // Create analysis config
        let config = AnalysisConfig {
            symbol_path: self.args.sympath.clone(),
            local_symbol_directories: self.args.local_symbol_directories.clone(),
            trace_pdb_loads: false,
            ignore_pdb_load_error: self.args.ignore_pdb_load_error,
            ignore_pe_load_error: false,
            include_wix_binaries: false,
            max_file_size_kb: self.args.max_file_size_kb,
            properties: std::collections::HashMap::new(),
        };

        // Analyze files
        let mut results = self.analyze_files(&files, &rules, &config)?;

        // Apply profile level overrides (only for builtin profiles that have level overrides)
        if let Some(ref builtin) = builtin_profile {
            self.apply_profile_levels(&mut results, builtin, &rules);
        }

        // Handle baseline comparison
        let comparison = baseline
            .as_ref()
            .map(|b| BaselineComparison::compare(&results, b));

        // If new_only flag is set, filter results to only show new issues
        if self.args.new_only
            && let Some(ref comp) = comparison
        {
            results.results = comp.new_issues.clone();
            results.results.extend(comp.passing_results.clone());
        }

        // Save baseline if requested
        if let Some(ref save_path) = self.args.save_baseline {
            let new_baseline = Baseline::from_results(&results);
            new_baseline.save(save_path)?;
            if !self.args.quiet {
                info!(
                    "Baseline saved to {} ({} issues)",
                    save_path.display(),
                    new_baseline.known_issues.len()
                );
            }
        }

        // Parse output format
        let output_format: OutputFormat = self
            .args
            .format
            .parse()
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        // Generate output based on format
        match output_format {
            OutputFormat::Text | OutputFormat::TextColor => {
                // Text output
                let use_colors = output_format == OutputFormat::TextColor;
                let formatter = TextFormatter::new(&rules)
                    .with_colors(use_colors)
                    .with_show_passed(self.args.show_passed);

                if let Some(ref output_path) = self.args.output {
                    // Write to file
                    let mut file = std::fs::File::create(output_path)?;
                    formatter.write(&mut file, &results)?;
                    if !self.args.quiet {
                        info!("Results written to {}", output_path.display());
                    }
                } else if !self.args.quiet {
                    // Print to console
                    let output = formatter.format(&results);
                    print!("{}", output);
                }
            }
            OutputFormat::Sarif => {
                // SARIF JSON output
                let mut sarif_logger = SarifLogger::new("Aldur", env!("CARGO_PKG_VERSION"));

                // Add rule descriptors
                for rule in &rules {
                    let desc = rule.descriptor();
                    // Build help text from fix_hint if available
                    let help = desc
                        .fix_hint
                        .as_ref()
                        .map(aldur_sarif::schema::MultiformatMessageString::text);
                    sarif_logger.add_rule(aldur_sarif::ReportingDescriptor {
                        id: desc.id.clone(),
                        name: Some(desc.name.clone()),
                        short_description: Some(
                            aldur_sarif::schema::MultiformatMessageString::text(
                                &desc.short_description,
                            ),
                        ),
                        full_description: Some(
                            aldur_sarif::schema::MultiformatMessageString::text(
                                &desc.full_description,
                            ),
                        ),
                        help_uri: Some(desc.help_uri.clone()),
                        help,
                        default_configuration: Some(aldur_sarif::schema::ReportingConfiguration {
                            enabled: Some(true),
                            level: Some(format!("{}", desc.default_level)),
                            parameters: None,
                        }),
                        message_strings: None,
                        properties: None,
                    });
                }

                // Add results
                sarif_logger.convert_analysis_result(&results);

                // Write output
                if let Some(ref output_path) = self.args.output {
                    sarif_logger.write_to_file(output_path)?;
                    if !self.args.quiet {
                        info!("Results written to {}", output_path.display());
                    }
                } else if !self.args.quiet {
                    // Print summary to console
                    let sarif = sarif_logger.build();
                    let json = serde_json::to_string_pretty(&sarif)?;
                    println!("{}", json);
                }
            }
            OutputFormat::GitHubActions => {
                // GitHub Actions output format
                let formatter =
                    GitHubActionsFormatter::new(&rules).with_show_passed(self.args.show_passed);

                if let Some(ref output_path) = self.args.output {
                    // Write to file
                    let mut file = std::fs::File::create(output_path)?;
                    formatter.write(&mut file, &results)?;
                    if !self.args.quiet {
                        info!("Results written to {}", output_path.display());
                    }
                } else if !self.args.quiet {
                    // Print to console
                    let output = formatter.format(&results);
                    print!("{}", output);
                }
            }
        }

        // Print multi-target summary if requested
        if self.args.summary || self.args.summary_markdown {
            let summary = MultiTargetSummary::from_results(&results, &rules);

            if self.args.summary_markdown {
                let md = summary.to_markdown();
                println!("{}", md);

                // Also write to GITHUB_STEP_SUMMARY if available
                if let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY")
                    && let Err(e) = std::fs::write(&summary_path, &md)
                {
                    warn!("Failed to write GitHub step summary: {}", e);
                }
            } else {
                let use_colors = std::io::stdout().is_terminal();
                let mut stdout = std::io::stdout();
                summary.write_text(&mut stdout, use_colors)?;
            }
        }

        // Print baseline comparison summary
        if let Some(ref comp) = comparison
            && !self.args.quiet
        {
            println!("\n📊 Baseline Comparison:");
            println!("  New issues:      {}", comp.new_issues.len());
            println!("  Existing issues: {}", comp.existing_issues.len());
            println!("  Fixed issues:    {}", comp.fixed_issues.len());

            if !comp.fixed_issues.is_empty() {
                println!("\n✅ Fixed since baseline:");
                for fixed in comp.fixed_issues.iter().take(5) {
                    println!("   - {} in {}", fixed.rule_id, fixed.target_name);
                }
                if comp.fixed_issues.len() > 5 {
                    println!("   ... and {} more", comp.fixed_issues.len() - 5);
                }
            }
        }

        // Print statistics
        if self.args.statistics {
            let elapsed = start_time.elapsed();
            println!("\nAnalysis Statistics:");
            println!("  Profile: {}", profile_name);
            println!("  Files analyzed: {}", results.files_analyzed);
            println!("  Errors: {}", results.error_count());
            println!("  Warnings: {}", results.warning_count());
            println!("  Time: {:.2}s", elapsed.as_secs_f64());
            println!(
                "  Files/sec: {:.2}",
                results.files_analyzed as f64 / elapsed.as_secs_f64()
            );
        }

        // Determine exit code based on baseline comparison if available
        let has_errors = if let Some(ref comp) = comparison {
            // When using baseline, only fail on NEW issues
            comp.has_new_errors()
        } else {
            results.has_errors()
        };

        let has_warnings = results.warning_count() > 0;

        // Return appropriate exit code:
        // 0 = success (no errors, no warnings)
        // 1 = errors present
        // 2 = no errors but warnings present
        if self.args.rich_return_code {
            let code = self.compute_rich_return_code(&results);
            std::process::exit(code);
        } else if has_errors {
            std::process::exit(1);
        } else if has_warnings {
            std::process::exit(2);
        }

        Ok(())
    }

    /// Apply profile level overrides to results based on rule tags
    fn apply_profile_levels(
        &self,
        results: &mut AnalysisResult,
        profile: &profiles::SecurityProfile,
        rules: &[Box<dyn Rule>],
    ) {
        // Build a lookup map from rule_id to descriptor
        let rule_descriptors: std::collections::HashMap<String, &aldur_core::RuleDescriptor> =
            rules
                .iter()
                .map(|r| (r.descriptor().id.clone(), r.descriptor()))
                .collect();

        for result in &mut results.results {
            if let Some(descriptor) = rule_descriptors.get(&result.rule_id)
                && let Some(level) = profile.get_rule_level(descriptor)
            {
                // Only upgrade severity, never downgrade
                if level > result.level {
                    result.level = level;
                }
            }
        }
    }

    fn collect_files(
        &self,
        spinner: Option<&ProgressBar>,
    ) -> Result<(Vec<AnalysisTarget>, Vec<tempfile::TempDir>)> {
        let mut files = Vec::new();
        let mut temp_dirs = Vec::new();

        // Helper to update spinner with file count
        let update_spinner = |count: usize| {
            if let Some(sp) = spinner {
                sp.set_message(format!("Discovering files... ({} found)", count));
            }
        };

        for target in &self.args.targets {
            // Strip trailing path separators to ensure consistent behavior across platforms
            // On Windows, paths ending with backslash may not be recognized by is_dir()
            let path = PathBuf::from(target.trim_end_matches(|c| c == '/' || c == '\\'));

            if path.is_file() {
                // Check if it's an archive
                if self.args.scan_archives && ArchiveExtractor::is_archive(&path) {
                    match self.extract_archive(&path) {
                        Ok((extracted, temp_dir)) => {
                            for binary in extracted {
                                files.push(AnalysisTarget {
                                    path: binary.extracted_path,
                                    display_name: binary.logical_path,
                                    archive_source: Some(binary.archive_source),
                                });
                            }
                            update_spinner(files.len());
                            temp_dirs.push(temp_dir);
                        }
                        Err(e) => {
                            warn!("Failed to extract archive {}: {}", path.display(), e);
                        }
                    }
                } else if self.is_valid_binary(&path) {
                    files.push(AnalysisTarget {
                        display_name: path.display().to_string(),
                        path,
                        archive_source: None,
                    });
                    update_spinner(files.len());
                }
            } else if path.is_dir() {
                // Check if it's an .app bundle
                if self.args.scan_archives && path.extension().is_some_and(|e| e == "app") {
                    match self.extract_archive(&path) {
                        Ok((extracted, temp_dir)) => {
                            for binary in extracted {
                                files.push(AnalysisTarget {
                                    path: binary.extracted_path,
                                    display_name: binary.logical_path,
                                    archive_source: Some(binary.archive_source),
                                });
                            }
                            update_spinner(files.len());
                            temp_dirs.push(temp_dir);
                        }
                        Err(e) => {
                            warn!("Failed to scan app bundle {}: {}", path.display(), e);
                        }
                    }
                } else {
                    self.collect_from_directory(&path, &mut files, &mut temp_dirs, spinner)?;
                }
            } else {
                // Try as glob pattern
                for p in glob::glob(target)
                    .context("Invalid glob pattern")?
                    .flatten()
                {
                    if p.is_file() {
                        if self.args.scan_archives && ArchiveExtractor::is_archive(&p) {
                            match self.extract_archive(&p) {
                                Ok((extracted, temp_dir)) => {
                                    for binary in extracted {
                                        files.push(AnalysisTarget {
                                            path: binary.extracted_path,
                                            display_name: binary.logical_path,
                                            archive_source: Some(binary.archive_source),
                                        });
                                    }
                                    update_spinner(files.len());
                                    temp_dirs.push(temp_dir);
                                }
                                Err(e) => {
                                    warn!("Failed to extract archive {}: {}", p.display(), e);
                                }
                            }
                        } else if self.is_valid_binary(&p) {
                            files.push(AnalysisTarget {
                                display_name: p.display().to_string(),
                                path: p,
                                archive_source: None,
                            });
                            update_spinner(files.len());
                        }
                    }
                }
            }
        }

        Ok((files, temp_dirs))
    }

    fn extract_archive(&self, path: &Path) -> Result<(Vec<ExtractedBinary>, tempfile::TempDir)> {
        let extractor = ArchiveExtractor::new(self.archive_config.clone());
        extractor.extract_binaries(path)
    }

    fn collect_from_directory(
        &self,
        dir: &Path,
        files: &mut Vec<AnalysisTarget>,
        temp_dirs: &mut Vec<tempfile::TempDir>,
        spinner: Option<&ProgressBar>,
    ) -> Result<()> {
        let walker = if self.args.recurse {
            WalkDir::new(dir)
        } else {
            WalkDir::new(dir).max_depth(1)
        };

        // Helper to update spinner with file count
        let update_spinner = |count: usize| {
            if let Some(sp) = spinner {
                sp.set_message(format!("Discovering files... ({} found)", count));
            }
        };

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                // Check if it's an archive
                if self.args.scan_archives && ArchiveExtractor::is_archive(path) {
                    match self.extract_archive(path) {
                        Ok((extracted, temp_dir)) => {
                            for binary in extracted {
                                files.push(AnalysisTarget {
                                    path: binary.extracted_path,
                                    display_name: binary.logical_path,
                                    archive_source: Some(binary.archive_source),
                                });
                            }
                            update_spinner(files.len());
                            temp_dirs.push(temp_dir);
                        }
                        Err(e) => {
                            warn!("Failed to extract archive {}: {}", path.display(), e);
                        }
                    }
                } else if self.is_valid_binary(path) {
                    files.push(AnalysisTarget {
                        display_name: path.display().to_string(),
                        path: path.to_path_buf(),
                        archive_source: None,
                    });
                    update_spinner(files.len());
                }
            }
        }

        Ok(())
    }

    fn is_valid_binary(&self, path: &Path) -> bool {
        // Check extension first
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();

            // Skip object files unless explicitly requested
            // Object files are intermediate build artifacts; linker-level security
            // flags (like -Wl,-z,noexecstack) aren't applied until final linking
            if ext_lower == "o" && !self.args.include_object_files {
                return false;
            }

            if matches!(
                ext_lower.as_str(),
                "dll" | "exe" | "sys" | "so" | "dylib" | "o" | ""
            ) {
                return aldur_parsers::can_load(path);
            }
        }

        // Try to load anyway for files without extension
        aldur_parsers::can_load(path)
    }

    fn analyze_files(
        &self,
        files: &[AnalysisTarget],
        rules: &[Box<dyn Rule>],
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult> {
        let total_files = files.len();
        let analyzed = AtomicUsize::new(0);

        let results: Vec<AnalysisResult> = files
            .par_iter()
            .filter_map(|target| {
                let result = self.analyze_file(&target.path, &target.display_name, rules, config);

                let count = analyzed.fetch_add(1, Ordering::SeqCst) + 1;
                #[allow(clippy::manual_is_multiple_of)]
                if !self.args.quiet && count % 100 == 0 {
                    debug!("Analyzed {}/{} files", count, total_files);
                }

                match result {
                    Ok(r) => Some(r),
                    Err(e) => {
                        if !self.args.quiet {
                            error!("Error analyzing {}: {}", target.display_name, e);
                        }
                        None
                    }
                }
            })
            .collect();

        // Merge results
        let mut combined = AnalysisResult::new();
        combined.files_analyzed = results.len();

        for result in results {
            combined.results.extend(result.results);
            combined.runtime_errors.extend(result.runtime_errors);
        }

        Ok(combined)
    }

    fn analyze_file(
        &self,
        path: &Path,
        display_name: &str,
        rules: &[Box<dyn Rule>],
        config: &AnalysisConfig,
    ) -> Result<AnalysisResult> {
        let mut result = AnalysisResult::new();
        result.files_analyzed = 1;

        // Load binary
        let binary = match aldur_parsers::load_binary(path) {
            Ok(b) => Arc::from(b),
            Err(e) => {
                result.add_runtime_error(format!("Failed to load {}: {}", display_name, e));
                return Ok(result);
            }
        };

        // Create analysis context with the display name
        let display_path = PathBuf::from(display_name);
        let mut context = AnalysisContext::new(display_path, config.clone());
        context.set_binary(binary);

        // Run applicable rules
        for rule in rules {
            let (applicability, reason) = rule.can_analyze(&context);

            match applicability {
                aldur_core::AnalysisApplicability::ApplicableToSpecifiedTarget => {
                    rule.analyze(&mut context);
                }
                _ => {
                    debug!(
                        "Rule {} not applicable to {}: {:?}",
                        rule.id(),
                        display_name,
                        reason
                    );
                }
            }
        }

        // Collect results
        result.results = context.take_results();

        Ok(result)
    }

    fn compute_rich_return_code(&self, results: &AnalysisResult) -> i32 {
        let mut code = 0i32;

        if results.has_errors() {
            code |= 0x80000000u32 as i32; // OneOrMoreErrorsFired
        }

        if results.warning_count() > 0 {
            code |= 0x40000000; // OneOrMoreWarningsFired
        }

        if !results.runtime_errors.is_empty() {
            code |= 0x40; // ExceptionInEngine
        }

        code
    }
}
