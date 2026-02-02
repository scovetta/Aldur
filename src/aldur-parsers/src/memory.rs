//! Memory management for binary loading
//!
//! This module provides a hybrid approach to loading binary data:
//! - Small files are read entirely into memory (safe, no unsafe code)
//! - Large files use memory mapping (unsafe but efficient)
//!
//! A global memory budget prevents OOM during archive scanning scenarios
//! where many files are loaded concurrently.

use memmap2::Mmap;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Default threshold for switching from heap allocation to mmap (10 MB)
pub const DEFAULT_MMAP_THRESHOLD: u64 = 10 * 1024 * 1024;

/// Default maximum heap memory budget for owned binary data (512 MB)
pub const DEFAULT_HEAP_BUDGET: usize = 512 * 1024 * 1024;

/// Binary data storage - either owned (heap) or memory-mapped
pub enum BinaryData {
    /// Data read into heap memory (safe, but uses RAM)
    Owned(Vec<u8>),
    /// Memory-mapped file (unsafe to create, but efficient for large files)
    Mapped(Mmap),
}

impl Deref for BinaryData {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            BinaryData::Owned(vec) => vec,
            BinaryData::Mapped(mmap) => mmap,
        }
    }
}

impl AsRef<[u8]> for BinaryData {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl BinaryData {
    /// Returns true if this data is heap-allocated
    pub fn is_owned(&self) -> bool {
        matches!(self, BinaryData::Owned(_))
    }

    /// Returns true if this data is memory-mapped
    pub fn is_mapped(&self) -> bool {
        matches!(self, BinaryData::Mapped(_))
    }

    /// Returns the size of the data
    pub fn len(&self) -> usize {
        self.deref().len()
    }

    /// Returns true if the data is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Tracks heap memory usage across all loaded binaries
///
/// This is thread-safe and can be shared across parallel analysis threads.
#[derive(Clone)]
pub struct MemoryBudget {
    /// Current heap usage in bytes
    used: Arc<AtomicUsize>,
    /// Maximum allowed heap usage in bytes
    limit: usize,
    /// Threshold above which files use mmap instead of heap
    mmap_threshold: u64,
}

impl Default for MemoryBudget {
    fn default() -> Self {
        Self::new(DEFAULT_HEAP_BUDGET, DEFAULT_MMAP_THRESHOLD)
    }
}

impl MemoryBudget {
    /// Create a new memory budget with custom limits
    ///
    /// # Arguments
    /// * `heap_limit` - Maximum bytes to allocate on heap for binary data
    /// * `mmap_threshold` - Files larger than this always use mmap
    pub fn new(heap_limit: usize, mmap_threshold: u64) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            limit: heap_limit,
            mmap_threshold,
        }
    }

    /// Create a memory budget that always uses mmap (no heap allocations)
    pub fn mmap_only() -> Self {
        Self::new(0, 0)
    }

    /// Create a memory budget that always uses heap (for testing/small workloads)
    pub fn heap_only(limit: usize) -> Self {
        Self::new(limit, u64::MAX)
    }

    /// Get current heap usage in bytes
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    /// Get the heap limit in bytes
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Get remaining heap budget in bytes
    pub fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.used())
    }

    /// Try to reserve `size` bytes from the heap budget
    ///
    /// Returns true if reservation succeeded, false if it would exceed budget
    fn try_reserve(&self, size: usize) -> bool {
        // Use compare-and-swap loop for thread safety
        loop {
            let current = self.used.load(Ordering::Relaxed);
            let new_total = current + size;

            if new_total > self.limit {
                return false;
            }

            match self.used.compare_exchange_weak(
                current,
                new_total,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue, // Another thread modified, retry
            }
        }
    }

    /// Release `size` bytes back to the heap budget
    fn release(&self, size: usize) {
        self.used.fetch_sub(size, Ordering::SeqCst);
    }

    /// Load binary data with memory budget management
    ///
    /// Decision logic:
    /// 1. If file > mmap_threshold → always use mmap
    /// 2. If file would exceed remaining budget → use mmap
    /// 3. Otherwise → read into heap
    pub fn load(&self, path: &Path) -> std::io::Result<BinaryData> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        // Large files always use mmap
        if file_size > self.mmap_threshold {
            return self.load_mapped(file);
        }

        let size_usize = file_size as usize;

        // Try to reserve heap space
        if self.try_reserve(size_usize) {
            match self.load_owned(file, size_usize) {
                Ok(data) => Ok(data),
                Err(e) => {
                    // Release the reservation on failure
                    self.release(size_usize);
                    Err(e)
                }
            }
        } else {
            // Budget exhausted, fall back to mmap
            self.load_mapped(file)
        }
    }

    /// Load file into heap memory
    fn load_owned(&self, mut file: File, size: usize) -> std::io::Result<BinaryData> {
        let mut buffer = Vec::with_capacity(size);
        file.read_to_end(&mut buffer)?;
        Ok(BinaryData::Owned(buffer))
    }

    /// Load file via memory mapping
    fn load_mapped(&self, file: File) -> std::io::Result<BinaryData> {
        // SAFETY: The file handle is held open for the duration of the Mmap's
        // lifetime (Mmap holds a reference to the file descriptor internally).
        // We open files read-only and do not modify them during parsing.
        // The mmap is used only for the duration of binary analysis.
        let mmap = unsafe { Mmap::map(&file) }?;
        Ok(BinaryData::Mapped(mmap))
    }

    /// Load from raw bytes (for archive extraction scenarios)
    ///
    /// This always uses heap since the data is already in memory.
    /// Returns an error if it would exceed the budget.
    pub fn load_from_bytes(&self, data: Vec<u8>) -> Result<BinaryData, MemoryBudgetExceeded> {
        let size = data.len();
        if self.try_reserve(size) {
            Ok(BinaryData::Owned(data))
        } else {
            Err(MemoryBudgetExceeded {
                requested: size,
                available: self.remaining(),
            })
        }
    }
}

/// Error returned when memory budget is exceeded
#[derive(Debug, Clone)]
pub struct MemoryBudgetExceeded {
    /// Bytes requested
    pub requested: usize,
    /// Bytes available
    pub available: usize,
}

impl std::fmt::Display for MemoryBudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Memory budget exceeded: requested {} bytes, only {} available",
            self.requested, self.available
        )
    }
}

impl std::error::Error for MemoryBudgetExceeded {}

/// Guard that releases memory when dropped
///
/// Use this when you need to track memory that will be released later.
pub struct MemoryGuard {
    budget: MemoryBudget,
    size: usize,
}

impl MemoryGuard {
    /// Create a new memory guard (does not reserve memory, just tracks it)
    pub fn new(budget: MemoryBudget, size: usize) -> Self {
        Self { budget, size }
    }
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        self.budget.release(self.size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_small_file_uses_heap() {
        let budget = MemoryBudget::new(1024 * 1024, 100 * 1024);

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"small content").unwrap();

        let data = budget.load(file.path()).unwrap();
        assert!(data.is_owned());
        assert_eq!(data.len(), 13);
    }

    #[test]
    fn test_large_file_uses_mmap() {
        let budget = MemoryBudget::new(1024 * 1024, 100); // Very low mmap threshold

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&vec![0u8; 200]).unwrap(); // Larger than threshold

        let data = budget.load(file.path()).unwrap();
        assert!(data.is_mapped());
    }

    #[test]
    fn test_budget_exhaustion_triggers_mmap() {
        let budget = MemoryBudget::new(100, 1024 * 1024); // Very small heap budget

        // First file fits in budget
        let mut file1 = NamedTempFile::new().unwrap();
        file1.write_all(&vec![0u8; 50]).unwrap();
        let data1 = budget.load(file1.path()).unwrap();
        assert!(data1.is_owned());

        // Second file exceeds remaining budget, falls back to mmap
        let mut file2 = NamedTempFile::new().unwrap();
        file2.write_all(&vec![0u8; 60]).unwrap();
        let data2 = budget.load(file2.path()).unwrap();
        assert!(data2.is_mapped());
    }

    #[test]
    fn test_concurrent_reservations() {
        use std::thread;

        let budget = MemoryBudget::new(1000, u64::MAX);
        let mut handles = vec![];

        for _ in 0..10 {
            let b = budget.clone();
            handles.push(thread::spawn(move || b.try_reserve(100)));
        }

        let successes: usize = handles
            .into_iter()
            .map(|h| if h.join().unwrap() { 1 } else { 0 })
            .sum();

        // Exactly 10 reservations of 100 bytes = 1000 bytes = full budget
        assert_eq!(successes, 10);
        assert_eq!(budget.used(), 1000);
    }

    #[test]
    fn test_mmap_only_mode() {
        let budget = MemoryBudget::mmap_only();

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"content").unwrap();

        let data = budget.load(file.path()).unwrap();
        assert!(data.is_mapped());
    }

    #[test]
    fn test_memory_guard_releases_on_drop() {
        let budget = MemoryBudget::new(1000, u64::MAX);
        budget.try_reserve(500);
        assert_eq!(budget.used(), 500);

        {
            let _guard = MemoryGuard::new(budget.clone(), 500);
            // Guard holds reference to 500 bytes
        }
        // Guard dropped, should release 500 bytes
        assert_eq!(budget.used(), 0);
    }
}
