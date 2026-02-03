//! Integration test for handling directory paths with trailing slashes

use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// Test that directory scanning works with trailing slashes
#[test]
fn test_directory_with_trailing_slash() {
    // Create a temporary directory with a test binary
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Copy the aldur binary itself as a test binary
    let aldur_binary = env!("CARGO_BIN_EXE_aldur");
    let test_binary = temp_path.join("test_binary");
    fs::copy(aldur_binary, &test_binary).unwrap();
    
    // Test without trailing slash
    let output_no_slash = Command::new(aldur_binary)
        .arg("analyze")
        .arg(temp_path.as_os_str())
        .output()
        .unwrap();
    
    // Test with trailing slash
    let path_with_slash = format!("{}/", temp_path.display());
    let output_with_slash = Command::new(aldur_binary)
        .arg("analyze")
        .arg(&path_with_slash)
        .output()
        .unwrap();
    
    // Test with trailing backslash (for Windows compatibility)
    let path_with_backslash = format!("{}\\", temp_path.display());
    let output_with_backslash = Command::new(aldur_binary)
        .arg("analyze")
        .arg(&path_with_backslash)
        .output()
        .unwrap();
    
    // All three should find files (exit code 0, 1, or 2 is fine, but not higher)
    // Exit code 0 = no errors/warnings, 1 = errors, 2 = warnings only
    assert!(output_no_slash.status.code().unwrap() <= 2, 
            "Without trailing slash should succeed (exit code <= 2)");
    assert!(output_with_slash.status.code().unwrap() <= 2, 
            "With trailing slash should succeed (exit code <= 2)");
    assert!(output_with_backslash.status.code().unwrap() <= 2, 
            "With trailing backslash should succeed (exit code <= 2)");
    
    // All three should find the same number of files (at least 1)
    let stdout_no_slash = String::from_utf8_lossy(&output_no_slash.stdout);
    let stdout_with_slash = String::from_utf8_lossy(&output_with_slash.stdout);
    let stdout_with_backslash = String::from_utf8_lossy(&output_with_backslash.stdout);
    
    assert!(stdout_no_slash.contains("Found 1 files to analyze"), 
            "Should find 1 file without trailing slash. Output: {}", stdout_no_slash);
    assert!(stdout_with_slash.contains("Found 1 files to analyze"), 
            "Should find 1 file with trailing slash. Output: {}", stdout_with_slash);
    assert!(stdout_with_backslash.contains("Found 1 files to analyze"), 
            "Should find 1 file with trailing backslash. Output: {}", stdout_with_backslash);
}

/// Test that directory scanning with recurse flag works with trailing slashes
#[test]
fn test_directory_with_trailing_slash_and_recurse() {
    // Create a temporary directory with a test binary
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Copy the aldur binary itself as a test binary
    let aldur_binary = env!("CARGO_BIN_EXE_aldur");
    let test_binary = temp_path.join("test_binary");
    fs::copy(aldur_binary, &test_binary).unwrap();
    
    // Test with recurse flag and trailing slash
    let path_with_slash = format!("{}/", temp_path.display());
    let output = Command::new(aldur_binary)
        .arg("analyze")
        .arg("-r")
        .arg(&path_with_slash)
        .output()
        .unwrap();
    
    // Should succeed (exit code 0, 1, or 2)
    assert!(output.status.code().unwrap() <= 2, 
            "Recurse with trailing slash should succeed (exit code <= 2)");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Found 1 files to analyze"), 
            "Should find at least 1 file with -r flag and trailing slash. Output: {}", stdout);
}

/// Test with multiple trailing slashes
#[test]
fn test_directory_with_multiple_trailing_slashes() {
    // Create a temporary directory with a test binary
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Copy the aldur binary itself as a test binary
    let aldur_binary = env!("CARGO_BIN_EXE_aldur");
    let test_binary = temp_path.join("test_binary");
    fs::copy(aldur_binary, &test_binary).unwrap();
    
    // Test with multiple trailing slashes
    let path_with_slashes = format!("{}/////", temp_path.display());
    let output = Command::new(aldur_binary)
        .arg("analyze")
        .arg(&path_with_slashes)
        .output()
        .unwrap();
    
    // Should succeed (exit code 0, 1, or 2)
    assert!(output.status.code().unwrap() <= 2, 
            "Multiple trailing slashes should succeed (exit code <= 2)");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Found 1 files to analyze"), 
            "Should find at least 1 file with multiple trailing slashes. Output: {}", stdout);
}
