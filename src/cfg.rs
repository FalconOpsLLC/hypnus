use alloc::string::String;
use core::ffi::c_void;

use obfstr::{obfstring as s};
use anyhow::{Context, Result, bail};
use dinvk::winapis::NtCurrentProcess;
use dinvk::helper::PE;

use crate::config::Config;
use crate::winapis::SetProcessValidCallTargets;
use crate::types::CFG_CALL_TARGET_INFO;

/// CFG_CALL_TARGET_VALID flag indicating a valid indirect call target.
const CFG_CALL_TARGET_VALID: usize = 1;

/// Adds a valid CFG call target for the given module base and target function.
pub fn add_cfg(module: usize, function: usize) -> Result<()> {
    unsafe {
        let nt_header = PE::parse(module as *mut c_void)
            .nt_header()
            .context(s!("invalid nt header"))?;

        // Memory range to apply the CFG policy
        let size = ((*nt_header).OptionalHeader.SizeOfImage as usize + 0xFFF) & !0xFFF;

        // Describe the valid call target (offset must be 16-byte aligned -- CFG bitmap granularity)
        let mut cfg = CFG_CALL_TARGET_INFO {
            Flags: CFG_CALL_TARGET_VALID,
            Offset: (function - module) & !0xF,
        };

        // Apply the new valid call target
        if SetProcessValidCallTargets(
            NtCurrentProcess(), 
            module as *mut c_void, 
            size, 
            1, 
            &mut cfg
        ) == 0 
        {
            bail!(s!("SetProcessValidCallTargets Failed"))
        }
    }

    Ok(())
}

/// Adds a valid CFG call target for a standalone allocation (not backed by a PE module).
/// Uses page-aligned base and page-sized region for SetProcessValidCallTargets.
pub fn add_cfg_standalone(function: usize) -> Result<()> {
    let page_base = function & !0xFFF;
    let offset = (function - page_base) & !0xF;
    let size = 0x1000;

    let mut cfg_info = CFG_CALL_TARGET_INFO {
        Flags: CFG_CALL_TARGET_VALID,
        Offset: offset,
    };

    if SetProcessValidCallTargets(
        NtCurrentProcess(),
        page_base as *mut c_void,
        size,
        1,
        &mut cfg_info
    ) == 0
    {
        bail!(s!("SetProcessValidCallTargets (standalone) Failed"))
    }

    Ok(())
}

/// Find the PE module base by scanning backwards from an address for the MZ header.
fn find_module_base(addr: usize) -> Option<usize> {
    let mut base = addr & !0xFFF;
    for _ in 0..2048 {
        if base < 0x1000 { break; }
        unsafe {
            let sig = *(base as *const u16);
            if sig == 0x5A4D {
                return Some(base);
            }
        }
        base -= 0x1000;
    }
    None
}

/// Register a stub address as a valid CFG target.
/// For image-backed stubs (inside a PE module), uses module-level registration.
/// For standalone allocations, uses page-level registration.
fn add_cfg_for_stub(addr: u64, _label: &str) {
    if addr == 0 {
        if cfg!(debug_assertions) {
            dinvk::println!("[CFG] skip {}: addr=0", _label);
        }
        return;
    }
    let addr_usize = addr as usize;

    if let Some(module_base) = find_module_base(addr_usize) {
        match add_cfg(module_base, addr_usize) {
            Ok(()) => {
                if cfg!(debug_assertions) {
                    dinvk::println!("[CFG] OK {}: 0x{:x} (mod 0x{:x}, off 0x{:x})",
                        _label, addr_usize, module_base, addr_usize - module_base);
                }
            }
            Err(_e) => {
                if cfg!(debug_assertions) {
                    dinvk::println!("[CFG] FAIL {}: 0x{:x} (mod 0x{:x}) - {}",
                        _label, addr_usize, module_base, _e);
                }
            }
        }
    } else {
        match add_cfg_standalone(addr_usize) {
            Ok(()) => {
                if cfg!(debug_assertions) {
                    dinvk::println!("[CFG] OK {} (standalone): 0x{:x}", _label, addr_usize);
                }
            }
            Err(_e) => {
                if cfg!(debug_assertions) {
                    dinvk::println!("[CFG] FAIL {} (standalone): 0x{:x} - {}",
                        _label, addr_usize, _e);
                }
            }
        }
    }
}

/// Registers known indirect call targets with Control Flow Guard (CFG).
pub fn register_cfg_targets(cfg: &Config) {
    if cfg!(debug_assertions) {
        dinvk::println!("[CFG] Registering targets...");
    }

    let targets = [(cfg.modules.ntdll, cfg.nt_continue)];
    for (module, func) in targets {
        match add_cfg(module.as_u64() as usize, func.as_u64() as usize) {
            Ok(()) => {
                if cfg!(debug_assertions) {
                    dinvk::println!("[CFG] OK NtContinue: 0x{:x}", func.as_u64());
                }
            }
            Err(_e) => {
                if cfg!(debug_assertions) {
                    dinvk::println!("[CFG] FAIL NtContinue: 0x{:x} - {}", func.as_u64(), _e);
                }
            }
        }
    }

    add_cfg_for_stub(cfg.custom_encrypt, "encrypt");
    add_cfg_for_stub(cfg.callback, "callback");
    add_cfg_for_stub(cfg.trampoline, "trampoline");
    add_cfg_for_stub(cfg.nt_set_event2_stub, "NtSetEvent2_stub");
    add_cfg_for_stub(cfg.fiber_trampoline, "fiber_tramp");

    if cfg!(debug_assertions) {
        dinvk::println!("[CFG] Registration complete");
    }
}
