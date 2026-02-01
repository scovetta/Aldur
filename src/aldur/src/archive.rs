//! Archive scanning support
//!
//! This module provides functionality for scanning binaries within archives.
//! Supported archive formats:
//! - ZIP (.zip, .jar, .war, .ear, .apk, .ipa, .msix, .msixbundle, .appx)
//! - TAR (.tar)
//! - Gzipped TAR (.tar.gz, .tgz)
//! - Bzip2 TAR (.tar.bz2, .tbz2)
//! - XZ TAR (.tar.xz, .txz)
//! - 7-Zip (.7z)
//! - Apple app bundles (.app directories)
//! - macOS packages (.pkg - xar format, handled as zip-like)

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tempfile::TempDir;
use tracing::{debug, info, warn};

/// Represents an archive type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveType {
    /// ZIP-based archives (zip, jar, war, ear, apk, ipa, msix, appx)
    Zip,
    /// Plain tar archive
    Tar,
    /// Gzipped tar archive
    TarGz,
    /// Bzip2 compressed tar archive
    TarBz2,
    /// XZ compressed tar archive
    TarXz,
    /// 7-Zip archive
    SevenZip,
    /// Apple app bundle (directory structure)
    AppBundle,
}

impl ArchiveType {
    /// Detect archive type from file path and magic bytes
    pub fn detect(path: &Path) -> Option<Self> {
        // First check by extension
        if let Some(archive_type) = Self::detect_by_extension(path) {
            return Some(archive_type);
        }

        // Then check by magic bytes
        Self::detect_by_magic(path)
    }

    /// Detect by file extension
    fn detect_by_extension(path: &Path) -> Option<Self> {
        let path_str = path.to_string_lossy().to_lowercase();

        // Handle double extensions first
        if path_str.ends_with(".tar.gz") || path_str.ends_with(".tgz") {
            return Some(Self::TarGz);
        }
        if path_str.ends_with(".tar.bz2")
            || path_str.ends_with(".tbz2")
            || path_str.ends_with(".tbz")
        {
            return Some(Self::TarBz2);
        }
        if path_str.ends_with(".tar.xz") || path_str.ends_with(".txz") {
            return Some(Self::TarXz);
        }

        // Check if it's an .app bundle directory
        if path.is_dir() && path_str.ends_with(".app") {
            return Some(Self::AppBundle);
        }

        // Single extensions
        let ext = path.extension()?.to_string_lossy().to_lowercase();

        match ext.as_str() {
            // ZIP-based
            "zip" | "jar" | "war" | "ear" | "apk" | "ipa" | "msix" | "msixbundle" | "appx"
            | "appxbundle" | "nupkg" | "xpi" | "crx" => Some(Self::Zip),
            // Plain tar
            "tar" => Some(Self::Tar),
            // 7-Zip
            "7z" => Some(Self::SevenZip),
            _ => None,
        }
    }

    /// Detect by magic bytes
    fn detect_by_magic(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic).ok()?;

        // ZIP magic: PK\x03\x04 or PK\x05\x06 (empty) or PK\x07\x08 (spanned)
        if magic[0..4] == [0x50, 0x4B, 0x03, 0x04]
            || magic[0..4] == [0x50, 0x4B, 0x05, 0x06]
            || magic[0..4] == [0x50, 0x4B, 0x07, 0x08]
        {
            return Some(Self::Zip);
        }

        // 7z magic: 7z\xBC\xAF\x27\x1C
        if magic[0..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
            return Some(Self::SevenZip);
        }

        // Gzip magic: \x1F\x8B
        if magic[0..2] == [0x1F, 0x8B] {
            return Some(Self::TarGz);
        }

        // Bzip2 magic: BZ (0x42, 0x5A)
        if magic[0..2] == [0x42, 0x5A] {
            return Some(Self::TarBz2);
        }

        // XZ magic: \xFD7zXZ\x00
        if magic[0..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
            return Some(Self::TarXz);
        }

        // TAR magic at offset 257: "ustar"
        let mut file = File::open(path).ok()?;
        let mut tar_magic = [0u8; 263];
        if file.read_exact(&mut tar_magic).is_ok() && &tar_magic[257..262] == b"ustar" {
            return Some(Self::Tar);
        }

        None
    }
}

/// Configuration for archive extraction
#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    /// Maximum uncompressed size in bytes (0 = unlimited)
    pub max_uncompressed_size: u64,
    /// Maximum number of entries to extract (0 = unlimited)
    pub max_entries: usize,
    /// Maximum depth for nested archives
    pub max_depth: usize,
    /// Whether to scan nested archives
    pub scan_nested: bool,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            max_uncompressed_size: 10 * 1024 * 1024 * 1024, // 10 GB
            max_entries: 100_000,
            max_depth: 3,
            scan_nested: true,
        }
    }
}

/// Represents an extracted binary from an archive
#[derive(Debug)]
pub struct ExtractedBinary {
    /// Path to the extracted file on disk
    pub extracted_path: PathBuf,
    /// Parent archive path
    pub archive_source: PathBuf,
    /// Full logical path (archive + path within)
    pub logical_path: String,
}

/// Archive extractor that handles different archive formats
pub struct ArchiveExtractor {
    config: ArchiveConfig,
}

impl ArchiveExtractor {
    pub fn new(config: ArchiveConfig) -> Self {
        Self { config }
    }

    /// Check if a path is a supported archive
    pub fn is_archive(path: &Path) -> bool {
        ArchiveType::detect(path).is_some()
    }

    /// Extract all binaries from an archive
    ///
    /// Returns extracted binaries and a TempDir that must be kept alive
    /// while the binaries are being used.
    pub fn extract_binaries(&self, archive_path: &Path) -> Result<(Vec<ExtractedBinary>, TempDir)> {
        let archive_type = ArchiveType::detect(archive_path)
            .ok_or_else(|| anyhow::anyhow!("Unknown archive type: {}", archive_path.display()))?;

        let temp_dir =
            TempDir::new().context("Failed to create temp directory for archive extraction")?;

        let mut binaries = Vec::new();

        info!(
            "Extracting {:?} archive: {}",
            archive_type,
            archive_path.display()
        );

        match archive_type {
            ArchiveType::Zip => {
                self.extract_zip(archive_path, temp_dir.path(), &mut binaries)?;
            }
            ArchiveType::Tar => {
                self.extract_tar(archive_path, temp_dir.path(), &mut binaries)?;
            }
            ArchiveType::TarGz => {
                self.extract_tar_gz(archive_path, temp_dir.path(), &mut binaries)?;
            }
            ArchiveType::TarBz2 => {
                self.extract_tar_bz2(archive_path, temp_dir.path(), &mut binaries)?;
            }
            ArchiveType::TarXz => {
                self.extract_tar_xz(archive_path, temp_dir.path(), &mut binaries)?;
            }
            ArchiveType::SevenZip => {
                self.extract_7z(archive_path, temp_dir.path(), &mut binaries)?;
            }
            ArchiveType::AppBundle => {
                self.extract_app_bundle(archive_path, temp_dir.path(), &mut binaries)?;
            }
        }

        // Handle nested archives if enabled
        if self.config.scan_nested {
            self.extract_nested_archives(archive_path, temp_dir.path(), &mut binaries, 1)?;
        }

        info!(
            "Extracted {} binaries from {}",
            binaries.len(),
            archive_path.display()
        );

        Ok((binaries, temp_dir))
    }

    /// Extract ZIP archive
    fn extract_zip(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        binaries: &mut Vec<ExtractedBinary>,
    ) -> Result<()> {
        let file = File::open(archive_path).context("Failed to open ZIP archive")?;
        let reader = BufReader::new(file);
        let mut archive = zip::ZipArchive::new(reader).context("Failed to read ZIP archive")?;

        let mut entry_count = 0;
        let mut total_size = 0u64;

        for i in 0..archive.len() {
            if self.config.max_entries > 0 && entry_count >= self.config.max_entries {
                warn!("Archive entry limit reached ({})", self.config.max_entries);
                break;
            }

            let mut entry = archive.by_index(i)?;
            let entry_name = entry.name().to_string();

            // Skip directories
            if entry.is_dir() {
                continue;
            }

            // Check size limits
            if self.config.max_uncompressed_size > 0 {
                total_size += entry.size();
                if total_size > self.config.max_uncompressed_size {
                    warn!(
                        "Archive size limit reached ({} bytes)",
                        self.config.max_uncompressed_size
                    );
                    break;
                }
            }

            // Sanitize path to prevent directory traversal
            let sanitized = Self::sanitize_path(&entry_name)?;
            let dest_path = dest_dir.join(&sanitized);

            // Create parent directories
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Check if this looks like a binary
            if Self::is_potential_binary(&entry_name) {
                // Extract the file
                let mut outfile = File::create(&dest_path)?;
                std::io::copy(&mut entry, &mut outfile)?;

                // Verify it's actually a binary
                if aldur_parsers::can_load(&dest_path) {
                    binaries.push(ExtractedBinary {
                        extracted_path: dest_path,
                        archive_source: archive_path.to_path_buf(),
                        logical_path: format!("{}!/{}", archive_path.display(), entry_name),
                    });
                }

                entry_count += 1;
            }
        }

        Ok(())
    }

    /// Extract plain TAR archive
    fn extract_tar(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        binaries: &mut Vec<ExtractedBinary>,
    ) -> Result<()> {
        let file = File::open(archive_path)?;
        let reader = BufReader::new(file);
        self.extract_tar_inner(reader, archive_path, dest_dir, binaries)
    }

    /// Extract gzipped TAR archive
    fn extract_tar_gz(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        binaries: &mut Vec<ExtractedBinary>,
    ) -> Result<()> {
        let file = File::open(archive_path)?;
        let reader = BufReader::new(file);
        let decoder = flate2::read::GzDecoder::new(reader);
        self.extract_tar_inner(decoder, archive_path, dest_dir, binaries)
    }

    /// Extract bzip2 TAR archive
    fn extract_tar_bz2(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        binaries: &mut Vec<ExtractedBinary>,
    ) -> Result<()> {
        let file = File::open(archive_path)?;
        let reader = BufReader::new(file);
        let decoder = bzip2::read::BzDecoder::new(reader);
        self.extract_tar_inner(decoder, archive_path, dest_dir, binaries)
    }

    /// Extract xz TAR archive
    fn extract_tar_xz(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        binaries: &mut Vec<ExtractedBinary>,
    ) -> Result<()> {
        let file = File::open(archive_path)?;
        let reader = BufReader::new(file);
        let decoder = xz2::read::XzDecoder::new(reader);
        self.extract_tar_inner(decoder, archive_path, dest_dir, binaries)
    }

    /// Common TAR extraction logic
    fn extract_tar_inner<R: Read>(
        &self,
        reader: R,
        archive_path: &Path,
        dest_dir: &Path,
        binaries: &mut Vec<ExtractedBinary>,
    ) -> Result<()> {
        let mut archive = tar::Archive::new(reader);
        let mut entry_count = 0;
        let mut total_size = 0u64;

        for entry_result in archive.entries()? {
            if self.config.max_entries > 0 && entry_count >= self.config.max_entries {
                warn!("Archive entry limit reached ({})", self.config.max_entries);
                break;
            }

            let mut entry = entry_result?;
            let entry_path = entry.path()?;
            let entry_name = entry_path.to_string_lossy().to_string();

            // Skip directories
            if entry.header().entry_type().is_dir() {
                continue;
            }

            // Check size limits
            let entry_size = entry.header().size()?;
            if self.config.max_uncompressed_size > 0 {
                total_size += entry_size;
                if total_size > self.config.max_uncompressed_size {
                    warn!(
                        "Archive size limit reached ({} bytes)",
                        self.config.max_uncompressed_size
                    );
                    break;
                }
            }

            // Sanitize path
            let sanitized = Self::sanitize_path(&entry_name)?;
            let dest_path = dest_dir.join(&sanitized);

            // Check if this looks like a binary
            if Self::is_potential_binary(&entry_name) {
                // Create parent directories
                if let Some(parent) = dest_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                // Extract the file
                let mut outfile = File::create(&dest_path)?;
                std::io::copy(&mut entry, &mut outfile)?;

                // Verify it's actually a binary
                if aldur_parsers::can_load(&dest_path) {
                    binaries.push(ExtractedBinary {
                        extracted_path: dest_path,
                        archive_source: archive_path.to_path_buf(),
                        logical_path: format!("{}!/{}", archive_path.display(), entry_name),
                    });
                }

                entry_count += 1;
            }
        }

        Ok(())
    }

    /// Extract 7z archive
    fn extract_7z(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        binaries: &mut Vec<ExtractedBinary>,
    ) -> Result<()> {
        use sevenz_rust2::{ArchiveEntry, ArchiveReader, Password};

        let file = File::open(archive_path)?;
        let mut reader =
            ArchiveReader::new(file, Password::empty()).context("Failed to read 7z archive")?;

        let mut entry_count = 0;

        reader.for_each_entries(|entry: &ArchiveEntry, reader: &mut dyn std::io::Read| {
            if self.config.max_entries > 0 && entry_count >= self.config.max_entries {
                return Ok(false); // Stop iteration
            }

            let entry_name = entry.name().to_string();

            // Skip directories
            if entry.is_directory() {
                return Ok(true);
            }

            // Check if this looks like a binary
            if Self::is_potential_binary(&entry_name) {
                // Sanitize path
                if let Ok(sanitized) = Self::sanitize_path(&entry_name) {
                    let dest_path = dest_dir.join(&sanitized);

                    // Create parent directories
                    if let Some(parent) = dest_path.parent() {
                        if std::fs::create_dir_all(parent).is_err() {
                            return Ok(true);
                        }
                    }

                    // Extract the file
                    let mut buffer = Vec::new();
                    if reader.read_to_end(&mut buffer).is_ok()
                        && std::fs::write(&dest_path, &buffer).is_ok()
                        && aldur_parsers::can_load(&dest_path)
                    {
                        binaries.push(ExtractedBinary {
                            extracted_path: dest_path,
                            archive_source: archive_path.to_path_buf(),
                            logical_path: format!("{}!/{}", archive_path.display(), entry_name),
                        });
                    }

                    entry_count += 1;
                }
            }

            Ok(true)
        })?;

        Ok(())
    }

    /// Extract Apple .app bundle (which is actually a directory structure)
    fn extract_app_bundle(
        &self,
        bundle_path: &Path,
        _dest_dir: &Path,
        binaries: &mut Vec<ExtractedBinary>,
    ) -> Result<()> {
        use walkdir::WalkDir;

        let mut entry_count = 0;

        for entry in WalkDir::new(bundle_path).into_iter().filter_map(|e| e.ok()) {
            if self.config.max_entries > 0 && entry_count >= self.config.max_entries {
                warn!(
                    "App bundle entry limit reached ({})",
                    self.config.max_entries
                );
                break;
            }

            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // Check if this looks like a binary
            let rel_path = path
                .strip_prefix(bundle_path)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            if Self::is_potential_binary(&rel_path) || aldur_parsers::can_load(path) {
                // For app bundles, we can just reference the file directly
                // No need to copy since it's a directory structure
                binaries.push(ExtractedBinary {
                    extracted_path: path.to_path_buf(),
                    archive_source: bundle_path.to_path_buf(),
                    logical_path: format!("{}!/{}", bundle_path.display(), rel_path),
                });

                entry_count += 1;
            }
        }

        Ok(())
    }

    /// Handle nested archives within an archive
    fn extract_nested_archives(
        &self,
        parent_archive: &Path,
        extracted_dir: &Path,
        binaries: &mut Vec<ExtractedBinary>,
        depth: usize,
    ) -> Result<()> {
        if depth >= self.config.max_depth {
            debug!(
                "Maximum nested archive depth reached ({})",
                self.config.max_depth
            );
            return Ok(());
        }

        // Find nested archives in the extracted directory
        let mut nested_archives = Vec::new();
        for entry in walkdir::WalkDir::new(extracted_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() && ArchiveType::detect(path).is_some() {
                nested_archives.push(path.to_path_buf());
            }
        }

        // Extract binaries from nested archives
        for nested_path in nested_archives {
            if let Ok((mut nested_binaries, _nested_temp)) = self.extract_binaries(&nested_path) {
                // Update logical paths to include parent archive
                for binary in &mut nested_binaries {
                    binary.logical_path =
                        format!("{}!/{}", parent_archive.display(), binary.logical_path);
                }
                binaries.extend(nested_binaries);
            }
        }

        Ok(())
    }

    /// Sanitize a path to prevent directory traversal attacks
    fn sanitize_path(path: &str) -> Result<PathBuf> {
        let path = PathBuf::from(path);
        let mut sanitized = PathBuf::new();

        for component in path.components() {
            match component {
                std::path::Component::Normal(c) => {
                    sanitized.push(c);
                }
                std::path::Component::CurDir => {} // Skip "."
                std::path::Component::ParentDir => {
                    // Don't go up, security risk
                    debug!("Skipping parent directory component in archive path");
                }
                std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                    // Skip absolute path components
                    debug!("Skipping absolute path component in archive path");
                }
            }
        }

        if sanitized.as_os_str().is_empty() {
            anyhow::bail!("Invalid archive entry path: {}", path.display());
        }

        Ok(sanitized)
    }

    /// Check if a path looks like it could be a binary file
    fn is_potential_binary(path: &str) -> bool {
        let lower = path.to_lowercase();

        // Skip directories
        if lower.ends_with('/') {
            return false;
        }

        // Skip common non-binary extensions
        let skip_extensions = [
            ".txt",
            ".md",
            ".rst",
            ".json",
            ".xml",
            ".yml",
            ".yaml",
            ".sh",
            ".bash",
            ".zsh",
            ".ps1",
            ".bat",
            ".cmd",
            ".py",
            ".pyc",
            ".pyo",
            ".rb",
            ".js",
            ".ts",
            ".tsx",
            ".jsx",
            ".java",
            ".kt",
            ".scala",
            ".go",
            ".rs",
            ".c",
            ".cpp",
            ".h",
            ".hpp",
            ".cs",
            ".fs",
            ".vb",
            ".html",
            ".htm",
            ".css",
            ".scss",
            ".less",
            ".sass",
            ".svg",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".ico",
            ".bmp",
            ".webp",
            ".mp3",
            ".mp4",
            ".wav",
            ".avi",
            ".mov",
            ".mkv",
            ".webm",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".zip",
            ".tar",
            ".gz",
            ".bz2",
            ".xz",
            ".7z",
            ".rar",
            ".pdb",
            ".idb",
            ".map",
            ".dSYM",
            ".plist",
            ".strings",
            ".nib",
            ".xib",
            ".storyboard",
            ".aar",
            ".apk",
            ".ipa",
            ".jar",
            ".war",
            ".ear",
            ".nuspec",
            ".nupkg",
            ".csproj",
            ".fsproj",
            ".vbproj",
            ".sln",
            ".toml",
            ".ini",
            ".cfg",
            ".conf",
            ".config",
            ".properties",
            ".lock",
            ".sum",
            ".mod",
            ".log",
            ".tmp",
            ".temp",
            ".cache",
            ".gitignore",
            ".gitattributes",
            ".editorconfig",
            ".license",
            ".licence",
            ".notice",
            ".md5",
            ".sha1",
            ".sha256",
            ".sha512",
            ".sig",
            ".asc",
        ];

        // Skip files with known non-binary extensions
        for ext in &skip_extensions {
            if lower.ends_with(ext) {
                return false;
            }
        }

        // Common binary extensions (definite yes)
        let binary_extensions = [
            ".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", // Windows PE
            ".so", ".o", ".a", // Linux ELF
            ".dylib", ".bundle", // macOS
            ".ko",     // Linux kernel module
        ];

        for ext in &binary_extensions {
            if lower.ends_with(ext) {
                return true;
            }
        }

        // Check common binary locations in app bundles
        if lower.contains("/macos/") || lower.contains("/contents/macos/") {
            return true;
        }

        // Check for Android native libraries
        if lower.contains("lib/") && lower.ends_with(".so") {
            return true;
        }

        // Files without extension in bin/lib directories might be binaries
        let has_extension = path
            .rsplit_once('.')
            .is_some_and(|(name, _)| !name.is_empty());
        if !has_extension {
            // Extensionless files could be ELF binaries (common on Unix)
            return true;
        }

        // Files in lib/bin directories that might be binaries
        if lower.contains("/lib/") || lower.contains("/bin/") || lower.contains("/sbin/") {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_type_detection() {
        assert_eq!(
            ArchiveType::detect_by_extension(Path::new("test.zip")),
            Some(ArchiveType::Zip)
        );
        assert_eq!(
            ArchiveType::detect_by_extension(Path::new("test.tar.gz")),
            Some(ArchiveType::TarGz)
        );
        assert_eq!(
            ArchiveType::detect_by_extension(Path::new("test.tar")),
            Some(ArchiveType::Tar)
        );
        assert_eq!(
            ArchiveType::detect_by_extension(Path::new("test.7z")),
            Some(ArchiveType::SevenZip)
        );
        assert_eq!(
            ArchiveType::detect_by_extension(Path::new("test.apk")),
            Some(ArchiveType::Zip)
        );
        assert_eq!(
            ArchiveType::detect_by_extension(Path::new("test.ipa")),
            Some(ArchiveType::Zip)
        );
    }

    #[test]
    fn test_sanitize_path() {
        assert_eq!(
            ArchiveExtractor::sanitize_path("foo/bar/baz.dll").unwrap(),
            PathBuf::from("foo/bar/baz.dll")
        );
        assert_eq!(
            ArchiveExtractor::sanitize_path("../../../etc/passwd").unwrap(),
            PathBuf::from("etc/passwd")
        );
        assert_eq!(
            ArchiveExtractor::sanitize_path("/absolute/path.exe").unwrap(),
            PathBuf::from("absolute/path.exe")
        );
    }

    #[test]
    fn test_is_potential_binary() {
        assert!(ArchiveExtractor::is_potential_binary("test.exe"));
        assert!(ArchiveExtractor::is_potential_binary("lib/native.dll"));
        assert!(ArchiveExtractor::is_potential_binary(
            "Contents/MacOS/MyApp"
        ));
        assert!(ArchiveExtractor::is_potential_binary(
            "lib/armeabi-v7a/libnative.so"
        ));
        assert!(!ArchiveExtractor::is_potential_binary("readme.txt"));
        assert!(!ArchiveExtractor::is_potential_binary("config.json"));
    }
}
