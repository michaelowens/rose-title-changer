use chrono::{DateTime, Utc};
use skidscan::Signature;
use std::str::FromStr;
use sysinfo::{PidExt, ProcessExt, SystemExt};
use widestring::U16String;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::windef::HWND;
use winapi::um::winuser::{SendMessageW, WM_SETTEXT};

use crate::process_memory::{self, WindowsProcess};
use crate::windows_api;

pub fn job_id_to_name(job_id: u32) -> String {
    let result = match job_id {
        0 => "Visitor",
        111 => "Soldier",
        121 => "Knight",
        122 => "Champion",
        211 => "Muse",
        221 => "Mage",
        222 => "Cleric",
        311 => "Hawker",
        321 => "Raider",
        322 => "Scout",
        411 => "Dealer",
        421 => "Bourgeois",
        422 => "Artisan",
        _ => "Unknown",
    };
    result.into()
}

#[allow(unused_must_use)]
pub fn sig_scan(
    process: &WindowsProcess,
    signature_str: &str,
    begin: usize,
    end: usize,
) -> Option<usize> {
    let sig = Signature::from_str(signature_str).unwrap();

    let mut buffer = vec![0; 4096];
    let mut current_chunk = begin;
    while current_chunk < end {
        process.read_bytes(current_chunk, &mut buffer);

        let result: Option<usize> = sig.scan(&buffer);
        if let Some(internal_address) = result {
            return Some(current_chunk + internal_address - 1); // why - 1?
        } else {
            current_chunk += buffer.len();
        }
    }

    None
}

pub fn find_process_window(pid: u32) -> Option<usize> {
    let mut maybe_window_handle = None;
    windows_api::enumerate_windows(|window| {
        let window_process_id = windows_api::window_thread_process_id(window).unwrap_or_default();

        if window_process_id != pid {
            return true;
        }

        maybe_window_handle = Some(window as usize);
        return false;
    });

    maybe_window_handle
}

pub fn get_debug_info(signature: &str) -> String {
    let mut debug_text = String::from("");

    /* #region Log some general information */
    let now: DateTime<Utc> = Utc::now();
    debug_text += &format!("Date: {}\n", now);

    let info = os_info::get();
    debug_text += &format!("OS: {}\n", info);
    debug_text += "\n";
    /* #endregion */

    /* #region test finding processes */
    let mut system = sysinfo::System::new();
    system.refresh_all(); //.refresh_processes();

    let mut found_pids: Vec<u32> = vec![];
    for proc in system.processes_by_exact_name("trose.exe") {
        found_pids.push(proc.pid().as_u32());
    }

    if found_pids.is_empty() {
        debug_text += "No";
    } else {
        debug_text += &found_pids.len().to_string();
    }
    debug_text += " trose.exe processes found!";
    debug_text += "\nPIDs: ";
    debug_text += &found_pids
        .iter()
        .map(|u| u.to_string())
        .collect::<Vec<String>>()
        .join(",");
    debug_text += "\n";
    debug_text += "\n";
    /* #endregion */

    /* #region test opening processes */
    for pid in found_pids {
        debug_text += &format!("[{}]\n", pid);
        let maybe_process = process_memory::open_process(pid);
        if maybe_process.is_none() {
            debug_text += "Failed to open process\n\n";
            continue;
        }
        debug_text += "Successfully opened process\n";

        let process = maybe_process.unwrap();

        let maybe_module = process.get_module_begin_end("trose.exe");
        // let maybe_module = self.get_module_begin_end(pid, process.handle, "trose.exe");
        if maybe_module.is_none() {
            debug_text += "Failed to find module begin and end\n\n";
            continue;
        }
        debug_text += "Successfully found module begin and end\n";

        let (base_address, module_end) = maybe_module.unwrap();
        debug_text += &format!("Module begin: {:#x}\n", base_address);
        debug_text += &format!("Module end:   {:#x}\n", module_end);

        let signature_address =
            sig_scan(&process, signature, base_address, module_end).unwrap_or(0);

        if signature_address == 0 {
            debug_text += "Failed to find function signature\n\n";
            continue;
        }
        debug_text += &format!(
            "Successfully found function signature: {:#x}\n",
            signature_address
        );

        let player_location_addr_offset =
            process.read_u32(signature_address + 0x07).unwrap_or(0) as usize;
        if player_location_addr_offset == 0 {
            debug_text += "Failed to read player location address\n\n";
            continue;
        }
        debug_text += &format!(
            "Successfully found player address location offset: {:#x}\n",
            player_location_addr_offset
        );

        let player_location_addr = signature_address + player_location_addr_offset + 11;
        debug_text += &format!("Player address location: {:#x}\n", player_location_addr);

        let player_address = process.read_u64(player_location_addr as usize).unwrap_or(0) as usize;
        if player_address == 0 {
            debug_text += "Failed to read player address\n\n";
            continue;
        }
        debug_text += &format!("Successfully found player address: {:#x}\n", player_address);

        let maybe_window_handle = find_process_window(process.pid);

        if maybe_window_handle.is_none() {
            debug_text += "Failed to find process window\n\n";
            continue;
        }
        debug_text += "Found process window handle\n";
        let window_handle = maybe_window_handle.unwrap();

        let player_name = process
            .read_string(player_address + 0x0B10)
            .unwrap_or_default();
        let player_job_id = process
            .read_u32(player_address + 0x3B1A)
            .unwrap_or_default();

        debug_text += &format!("Player name: {}\n", player_name);
        debug_text += &format!(
            "Player job: {} ({})\n",
            player_job_id,
            job_id_to_name(player_job_id)
        );

        // try to fetch original title to revert
        let original_title = windows_api::window_get_title(window_handle);

        let title = U16String::from("debug title") + "\0";
        let send_message_result;
        unsafe {
            send_message_result = SendMessageW(
                window_handle as HWND,
                WM_SETTEXT,
                0,
                title.as_ptr() as LPARAM,
            );
        }
        debug_text += &format!(
            "Tried changing window title, result: {}\n",
            send_message_result
        );
        unsafe {
            SendMessageW(
                window_handle as HWND,
                WM_SETTEXT,
                0,
                U16String::from(original_title).as_ptr() as LPARAM,
            );
        }
    }
    /* #endregion */

    debug_text
}
