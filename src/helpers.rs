use skidscan::Signature;
use std::mem;
use std::str::FromStr;
use widestring::U16String;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{BOOL, LPARAM};
use winapi::shared::windef::HWND;
use winapi::um::winuser::{EnumWindows, SendMessageW, WM_SETTEXT};

use crate::process_memory::WindowsProcess;

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

pub fn window_set_title(hwnd: HWND, title: &str) {
    if hwnd.is_null() {
        return;
    }

    let title = U16String::from(title) + "\0";
    unsafe {
        SendMessageW(hwnd, WM_SETTEXT, 0, title.as_ptr() as LPARAM);
    }
}

pub fn enumerate_windows<F>(mut callback: F)
where
    F: FnMut(HWND) -> bool,
{
    let mut trait_obj: &mut dyn FnMut(HWND) -> bool = &mut callback;
    let closure_pointer_pointer: *mut c_void = unsafe { mem::transmute(&mut trait_obj) };

    let lparam = closure_pointer_pointer as LPARAM;
    unsafe { EnumWindows(Some(enumerate_callback), lparam) };
}

unsafe extern "system" fn enumerate_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let closure: &mut &mut dyn FnMut(HWND) -> bool = mem::transmute(lparam as *mut c_void);
    if closure(hwnd) {
        1
    } else {
        0
    }
}
