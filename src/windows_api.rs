use std::mem;

use eframe::IconData;
use widestring::U16String;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::BOOL;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::windef::HDC;
use winapi::shared::windef::HICON;
use winapi::shared::windef::HWND;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::wingdi::CreateCompatibleDC;
use winapi::um::wingdi::DeleteDC;
use winapi::um::wingdi::GetDIBits;
use winapi::um::wingdi::GetObjectA;
use winapi::um::wingdi::SelectObject;
use winapi::um::wingdi::BITMAP;
use winapi::um::wingdi::BITMAPINFO;
use winapi::um::wingdi::BITMAPINFOHEADER;
use winapi::um::wingdi::BI_RGB;
use winapi::um::wingdi::DIB_RGB_COLORS;
use winapi::um::winuser::EnumWindows;
use winapi::um::winuser::GetIconInfo;
use winapi::um::winuser::GetWindowThreadProcessId;
use winapi::um::winuser::LoadImageW;
use winapi::um::winuser::SendMessageW;
use winapi::um::winuser::ICONINFO;
use winapi::um::winuser::IMAGE_ICON;
use winapi::um::winuser::LR_DEFAULTCOLOR;
use winapi::um::winuser::WM_GETTEXT;
use winapi::um::winuser::WM_GETTEXTLENGTH;
use winapi::um::winuser::WM_SETTEXT;

// Grab the icon from the exe and hand it over to egui
pub fn load_app_icon() -> IconData {
    let (mut buffer, width, height) = unsafe {
        let h_instance = GetModuleHandleW(0 as *const u16); //.expect("Failed to get HINSTANCE");
        let icon = LoadImageW(
            h_instance,
            (U16String::from("id") + "\0").as_ptr(),
            IMAGE_ICON,
            512,
            512,
            LR_DEFAULTCOLOR,
        );
        //.expect("Failed to load icon");

        let mut icon_info = ICONINFO::default();
        let res = GetIconInfo(icon as HICON, &mut icon_info as *mut _);
        if res == 0 {
            panic!("Failed to load icon info");
        }

        let mut bitmap = BITMAP::default();
        GetObjectA(
            icon_info.hbmColor as *mut _,
            std::mem::size_of::<BITMAP>() as i32,
            &mut bitmap as *mut _ as *mut _,
        );

        let width = bitmap.bmWidth;
        let height = bitmap.bmHeight;

        let b_size = (width * height * 4) as usize;
        let mut buffer = Vec::<u8>::with_capacity(b_size);

        let h_dc = CreateCompatibleDC(0 as HDC);
        let h_bitmap = SelectObject(h_dc, icon_info.hbmColor as _);

        let mut bitmap_info = BITMAPINFO::default();
        bitmap_info.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bitmap_info.bmiHeader.biWidth = width;
        bitmap_info.bmiHeader.biHeight = height;
        bitmap_info.bmiHeader.biPlanes = 1;
        bitmap_info.bmiHeader.biBitCount = 32;
        bitmap_info.bmiHeader.biCompression = BI_RGB;
        bitmap_info.bmiHeader.biSizeImage = 0;

        let res = GetDIBits(
            h_dc,
            icon_info.hbmColor,
            0,
            height as u32,
            buffer.spare_capacity_mut().as_mut_ptr() as *mut _,
            &mut bitmap_info as *mut _,
            DIB_RGB_COLORS,
        );
        if res == 0 {
            panic!("Failed to get RGB DI bits");
        }

        SelectObject(h_dc, h_bitmap);
        DeleteDC(h_dc);

        assert_eq!(
            bitmap_info.bmiHeader.biSizeImage as usize, b_size,
            "returned biSizeImage must equal to b_size"
        );

        // set the new size
        buffer.set_len(bitmap_info.bmiHeader.biSizeImage as usize);

        (buffer, width as u32, height as u32)
    };

    // RGBA -> BGRA
    for pixel in buffer.as_mut_slice().chunks_mut(4) {
        pixel.swap(0, 2);
    }

    // Flip the image vertically
    let row_size = width as usize * 4; // number of pixels in each row
    let row_count = buffer.len() as usize / row_size; // number of rows in the image
    for row in 0..row_count / 2 {
        // loop through half of the rows
        let start = row * row_size; // index of the start of the current row
        let end = (row_count - row - 1) * row_size; // index of the end of the current row
        for i in 0..row_size {
            buffer.swap(start + i, end + i);
        }
    }

    IconData {
        rgba: buffer,
        width,
        height,
    }
}

pub fn window_get_title(hwnd: usize) -> String {
    let text_length = unsafe { SendMessageW(hwnd as HWND, WM_GETTEXTLENGTH, 0, 0) + 1 };
    let mut text_buffer = Vec::<u16>::with_capacity(text_length as usize);

    unsafe {
        SendMessageW(
            hwnd as HWND,
            WM_GETTEXT,
            text_length as usize,
            text_buffer.as_mut_ptr() as LPARAM,
        );
    }

    String::from_utf16_lossy(&text_buffer)
}

pub fn window_set_title(hwnd: usize, title: &str) {
    if hwnd == 0 {
        return;
    }

    let title = U16String::from(title) + "\0";
    unsafe {
        SendMessageW(hwnd as HWND, WM_SETTEXT, 0, title.as_ptr() as LPARAM);
    }
}

pub fn window_thread_process_id(hwnd: HWND) -> Option<u32> {
    let mut window_process_id = 0;
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut window_process_id);
    }

    if window_process_id > 0 {
        Some(window_process_id)
    } else {
        None
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
        true.into()
    } else {
        false.into()
    }
}
