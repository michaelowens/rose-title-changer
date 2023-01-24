// Modified and simplied version of https://crates.io/crates/process-memory-reader

//! ```no_run
//! use process_memory::Process;
//!
//! let process = process_memory::open_process(22212).unwrap();
//! let base_address = process.base_address("Notepad.exe").unwrap();
//!
//! process.read_u8(base_address + 0x127).unwrap();
//! ```

use std::{
    ffi::OsString, io::Error as IoError, mem::size_of, os::windows::prelude::OsStringExt, ptr,
};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::TRUE;
use winapi::um::{
    handleapi::CloseHandle,
    memoryapi::ReadProcessMemory,
    processthreadsapi::OpenProcess,
    tlhelp32::{
        CreateToolhelp32Snapshot, Module32First, Module32Next, Process32FirstW, Process32NextW,
        MODULEENTRY32, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
    },
    winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
};

#[derive(Debug)]
pub enum MemoryReadError {
    InaccessibleMemoryAddress { address: usize },
    LessBytesRead { expected: usize, actual: usize },
    IOError { io_error: IoError },
}

impl From<IoError> for MemoryReadError {
    fn from(io_error: IoError) -> Self {
        MemoryReadError::IOError { io_error }
    }
}

macro_rules! define_number_read {
    ($type: ident, $name: ident, $bytes: expr) => {
        #[allow(dead_code)]
        pub fn $name(&self, address: usize) -> Result<$type, MemoryReadError> {
            let mut buffer = [0u8; $bytes];
            self.read_bytes(address, &mut buffer)?;
            Ok($type::from_le_bytes(buffer))
        }
    };
}

/// Opens process with specified id.
pub fn open_process(pid: u32) -> Option<WindowsProcess> {
    let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    Some(WindowsProcess { pid, handle })
}

#[allow(dead_code)]
/// Finds all processes matching `name`
pub fn find_by_name(name: &str) -> Vec<WindowsProcess> {
    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let mut processes = Vec::new();

    if handle.is_null() {
        return processes;
    }

    let mut entry = PROCESSENTRY32W::default();
    unsafe { ptr::write(&mut entry.dwSize, size_of::<PROCESSENTRY32W>() as u32) };

    if unsafe { Process32FirstW(handle, &mut entry) } == TRUE {
        while unsafe { Process32NextW(handle, &mut entry) == TRUE } {
            let process_name_full = &entry.szExeFile;
            let process_name_length = process_name_full.iter().take_while(|&&c| c != 0).count();
            let process_name = &OsString::from_wide(&process_name_full[..process_name_length]);

            if process_name != name {
                continue;
            }

            open_process(entry.th32ProcessID).map(|process| processes.push(process));
        }
    }

    unsafe { CloseHandle(handle) };

    processes
}

#[derive(Debug)]
pub struct WindowsProcess {
    pub pid: u32,
    pub handle: *mut c_void,
}

impl WindowsProcess {
    pub fn get_module_begin_end(&self, module_name: &str) -> Option<(usize, usize)> {
        let handle =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) };

        if handle.is_null() {
            return None;
        }

        let mut module_entry = MODULEENTRY32::default();
        module_entry.dwSize = size_of::<MODULEENTRY32>() as u32;

        let result = unsafe { Module32First(handle, &mut module_entry) };

        if result != TRUE {
            return None;
        }

        loop {
            let module_name_bytes: Vec<i8> =
                module_name.as_bytes().iter().map(|&i| i as i8).collect();
            if &module_entry.szModule[0..9] == &*module_name_bytes {
                break;
            }

            let next_result = unsafe { Module32Next(handle, &mut module_entry) };
            if next_result != TRUE {
                break;
            }
        }

        unsafe { CloseHandle(handle) };
        Some((
            module_entry.modBaseAddr as usize,
            ((module_entry.modBaseAddr as usize) + (module_entry.modBaseSize as usize)),
        ))
    }

    pub fn read_string(&self, address: usize) -> Result<String, MemoryReadError> {
        let mut buffer = Vec::new();
        let mut index = 0;

        loop {
            let ch = self.read_u8(address + index as usize)?;
            if ch == 0 {
                break;
            }

            buffer.insert(index, ch);
            index += 1;
        }

        Ok(String::from_utf8(buffer).unwrap_or(String::from("")))
    }

    pub fn read_u8(&self, address: usize) -> Result<u8, MemoryReadError> {
        let mut buffer = [0u8; 1];
        self.read_bytes(address, &mut buffer)?;
        Ok(buffer[0])
    }

    pub fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<(), MemoryReadError> {
        let mut read: usize = 0;
        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                &mut read,
            )
        };

        if result != TRUE {
            return Err(MemoryReadError::InaccessibleMemoryAddress { address });
        }

        if read != buffer.len() {
            return Err(MemoryReadError::LessBytesRead {
                expected: buffer.len(),
                actual: read,
            });
        }

        Ok(())
    }

    define_number_read!(u32, read_u32, 4);
    define_number_read!(u64, read_u64, 8);
    define_number_read!(u128, read_u128, 16);
    define_number_read!(i32, read_i32, 4);
    define_number_read!(i64, read_i64, 8);
    define_number_read!(f32, read_f32, 4);
    define_number_read!(f64, read_f64, 8);
}

impl Drop for WindowsProcess {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}
