#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use chrono::{DateTime, Utc};
use core::time;
use eframe::egui::{self, RichText, TextEdit, TextStyle};
use eframe::epaint::{FontFamily, FontId};
use eframe::Theme;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use widestring::U16String;
use winapi::shared::minwindef::LPARAM;
use winapi::shared::windef::{HWND, HWND__};
use winapi::um::winuser::{
    GetWindowThreadProcessId, SendMessageW, WM_GETTEXT, WM_GETTEXTLENGTH, WM_SETTEXT,
};

mod helpers;
mod process_memory;
use crate::helpers::*;

fn main() {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(320.0, 240.0)),
        resizable: false,
        follow_system_theme: false,
        default_theme: Theme::Dark,
        ..Default::default()
    };
    eframe::run_native(
        "ROSE Title Changer",
        options.clone(),
        Box::new(|cc| {
            let mut app = MyApp::new(cc);
            app.start_timer(&cc.egui_ctx);
            Box::new(app)
        }),
    );
}

#[inline]
fn tableheading() -> TextStyle {
    TextStyle::Name("TableHeading".into())
}

fn configure_text_styles(ctx: &egui::Context) {
    use FontFamily::{Monospace, Proportional};

    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Heading, FontId::new(25.0, Proportional)),
        (tableheading(), FontId::new(18.0, Proportional)),
        (TextStyle::Body, FontId::new(16.0, Proportional)),
        (TextStyle::Monospace, FontId::new(16.0, Monospace)),
        (TextStyle::Button, FontId::new(14.0, Proportional)),
        (TextStyle::Small, FontId::new(12.0, Proportional)),
    ]
    .into();
    ctx.set_style(style);
}

#[derive(Debug)]
struct Game {
    pid: u32,
    signature_address: usize,
    player_address: usize,
    window_handle: usize,
    title: String,
}

#[derive(Clone)]
struct MyApp {
    show_username: Arc<Mutex<bool>>,
    show_job: Arc<Mutex<bool>>,
    system: Arc<Mutex<System>>,
    games: Arc<Mutex<HashMap<u32, Game>>>,
    show_debug: Arc<Mutex<bool>>,
    debug_text: Arc<Mutex<String>>,
}

impl MyApp {
    fn new(cc: &eframe::CreationContext) -> Self {
        configure_text_styles(&cc.egui_ctx);
        // TODO: find a better way than wrapping everything in Arc/Mutex
        Self {
            show_username: Arc::new(Mutex::new(true)),
            show_job: Arc::new(Mutex::new(true)),
            system: Arc::new(Mutex::new(sysinfo::System::new())),
            games: Arc::new(Mutex::new(HashMap::new())),
            show_debug: Arc::new(Mutex::new(false)),
            debug_text: Arc::new(Mutex::new("".into())),
        }
    }

    fn start_timer(&mut self, ectx: &egui::Context) {
        let mut me = self.clone();
        let ctx = ectx.clone();
        thread::spawn(move || loop {
            me.find_games();
            ctx.request_repaint();
            thread::sleep(time::Duration::from_secs(5));
        });
    }

    fn find_games(&mut self) {
        let mut system = self.system.lock().unwrap();
        let mut games = self.games.lock().unwrap();
        system.refresh_all(); //.refresh_processes();

        let mut found_pids: Vec<u32> = vec![];
        for proc in system.processes_by_exact_name("trose.exe") {
            found_pids.push(proc.pid().as_u32());

            let maybe_process = process_memory::open_process(proc.pid().as_u32());
            if maybe_process.is_none() {
                continue;
            }
            let process = maybe_process.unwrap();

            let signature_address;
            if games.contains_key(&process.pid)
                && games.get(&process.pid).unwrap().player_address != 0
            {
                // if the game was found before and has a player address we can skip the signature scan
                let old = games.get(&process.pid).unwrap();
                signature_address = old.signature_address;
            } else {
                let maybe_module = process.get_module_begin_end("trose.exe");
                if maybe_module.is_none() {
                    continue;
                }
                let (base_address, module_end) = maybe_module.unwrap();
                let signature = "? 83 EC 28 ? 8B 05 75 E5 FF 00 ? 85 C0 ? 24 ? 38 6B 00 00 ? 73 14 F4 FF ? 89 44 24 30 ? 85 C0";
                signature_address =
                    sig_scan(&process, signature, base_address, module_end).unwrap_or(0);
            }

            let mut player_address = 0;
            if signature_address != 0 {
                let player_location_addr_offset =
                    process.read_u32(signature_address + 0x07).unwrap_or(0) as usize;
                if player_location_addr_offset != 0 {
                    let player_location_addr = signature_address + player_location_addr_offset + 11;

                    player_address =
                        process.read_u64(player_location_addr as usize).unwrap_or(0) as usize;
                }
            }

            let mut window_process_id = 0;
            let mut window_handle = 0;
            enumerate_windows(|window| {
                unsafe {
                    GetWindowThreadProcessId(window, &mut window_process_id);
                }

                if window_process_id != process.pid {
                    return true;
                }

                window_handle = window as usize;
                return false;
            });

            games.insert(
                process.pid,
                Game {
                    pid: process.pid,
                    signature_address,
                    player_address,
                    window_handle,
                    title: "".into(),
                },
            );
        }

        // Remove windows that have been closed
        games.retain(|&k, _| found_pids.contains(&k));

        drop(system);
        drop(games);
        self.set_titles();
    }

    fn set_titles(&mut self) {
        let mut games = self.games.lock().unwrap();
        for (_pid, game) in games.iter_mut() {
            if game.player_address == 0 {
                continue;
            }

            let maybe_process = process_memory::open_process(game.pid);
            if maybe_process.is_none() {
                continue;
            }
            let process = maybe_process.unwrap();

            let mut title_parts: Vec<String> = vec![];
            let player_name = process
                .read_string(game.player_address + 0x0B10)
                .unwrap_or_default();
            let player_job_id = process
                .read_u32(game.player_address + 0x3B1A)
                .unwrap_or_default();

            let show_username = self.show_username.lock().unwrap();
            let show_job = self.show_job.lock().unwrap();
            if *show_username {
                title_parts.push(player_name);
            }

            if *show_job {
                title_parts.push(job_id_to_name(player_job_id));
            }
            drop(show_username);
            drop(show_job);

            game.title = title_parts.join(" - ");

            window_set_title(game.window_handle as HWND, &game.title);
        }
    }

    fn run_debug(&mut self) {
        let mut show_debug = self.show_debug.lock().unwrap();
        let mut debug_text = self.debug_text.lock().unwrap();
        let mut system = self.system.lock().unwrap();

        *debug_text = "".to_string();

        /* #region Log some general information */
        let now: DateTime<Utc> = Utc::now();
        *debug_text += &format!("Date: {}\n", now);

        let info = os_info::get();
        *debug_text += &format!("OS: {}\n", info);
        *debug_text += "\n";
        /* #endregion */

        /* #region test finding processes */
        system.refresh_all(); //.refresh_processes();

        let mut found_pids: Vec<u32> = vec![];
        for proc in system.processes_by_exact_name("trose.exe") {
            found_pids.push(proc.pid().as_u32());
        }

        if found_pids.is_empty() {
            *debug_text += "No";
        } else {
            *debug_text += &found_pids.len().to_string();
        }
        *debug_text += " trose.exe processes found!";
        *debug_text += "\nPIDs: ";
        *debug_text += &found_pids
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<String>>()
            .join(",");
        *debug_text += "\n";
        *debug_text += "\n";
        /* #endregion */

        /* #region test opening processes */
        for pid in found_pids {
            *debug_text += &format!("[{}]\n", pid);
            let maybe_process = process_memory::open_process(pid);
            if maybe_process.is_none() {
                *debug_text += "Failed to open process\n\n";
                continue;
            }
            *debug_text += "Successfully opened process\n";

            let process = maybe_process.unwrap();

            let maybe_module = process.get_module_begin_end("trose.exe");
            // let maybe_module = self.get_module_begin_end(pid, process.handle, "trose.exe");
            if maybe_module.is_none() {
                *debug_text += "Failed to find module begin and end\n\n";
                continue;
            }
            *debug_text += "Successfully found module begin and end\n";

            let (base_address, module_end) = maybe_module.unwrap();
            *debug_text += &format!("Module begin: {:#x}\n", base_address);
            *debug_text += &format!("Module end:   {:#x}\n", module_end);

            let signature = "? 83 EC 28 ? 8B 05 75 E5 FF 00 ? 85 C0 ? 24 ? 38 6B 00 00 ? 73 14 F4 FF ? 89 44 24 30 ? 85 C0";
            let signature_address =
                sig_scan(&process, signature, base_address, module_end).unwrap_or(0);

            if signature_address == 0 {
                *debug_text += "Failed to find function signature\n\n";
                continue;
            }
            *debug_text += &format!(
                "Successfully found function signature: {:#x}\n",
                signature_address
            );

            let player_location_addr_offset =
                process.read_u32(signature_address + 0x07).unwrap_or(0) as usize;
            if player_location_addr_offset == 0 {
                *debug_text += "Failed to read player location address\n\n";
                continue;
            }
            *debug_text += &format!(
                "Successfully found player address location offset: {:#x}\n",
                player_location_addr_offset
            );

            let player_location_addr = signature_address + player_location_addr_offset + 11;
            *debug_text += &format!("Player address location: {:#x}\n", player_location_addr);

            let player_address =
                process.read_u64(player_location_addr as usize).unwrap_or(0) as usize;
            if player_address == 0 {
                *debug_text += "Failed to read player address\n\n";
                continue;
            }
            *debug_text += &format!("Successfully found player address: {:#x}\n", player_address);

            let mut window_process_id = 0;
            let mut window_handle = 0;
            enumerate_windows(|window| {
                unsafe {
                    GetWindowThreadProcessId(window, &mut window_process_id);
                }

                if window_process_id != process.pid {
                    return true;
                }

                window_handle = window as usize;
                return false;
            });

            if window_handle == 0 {
                *debug_text += "Failed to find process window\n\n";
                continue;
            }
            *debug_text += "Found process window handle\n";

            let player_name = process
                .read_string(player_address + 0x0B10)
                .unwrap_or_default();
            let player_job_id = process
                .read_u32(player_address + 0x3B1A)
                .unwrap_or_default();

            *debug_text += &format!("Player name: {}\n", player_name);
            *debug_text += &format!(
                "Player job: {} ({})\n",
                player_job_id,
                job_id_to_name(player_job_id)
            );

            // try to fetch original title to revert
            let original_title;
            unsafe {
                let text_length =
                    SendMessageW(window_handle as *mut HWND__, WM_GETTEXTLENGTH, 0, 0) + 1;
                let mut text_buffer = Vec::<u16>::with_capacity(text_length as usize);

                SendMessageW(
                    window_handle as *mut HWND__,
                    WM_GETTEXT,
                    text_length as usize,
                    text_buffer.as_mut_ptr() as LPARAM,
                );

                original_title = String::from_utf16_lossy(&text_buffer);
            }

            let title = U16String::from("debug title") + "\0";
            let send_message_result;
            unsafe {
                send_message_result = SendMessageW(
                    window_handle as *mut HWND__,
                    WM_SETTEXT,
                    0,
                    title.as_ptr() as LPARAM,
                );
            }
            *debug_text += &format!(
                "Tried changing window title, result: {}\n",
                send_message_result
            );
            unsafe {
                SendMessageW(
                    window_handle as *mut HWND__,
                    WM_SETTEXT,
                    0,
                    U16String::from(original_title).as_ptr() as LPARAM,
                );
            }
        }
        /* #endregion */

        *show_debug = true;
        drop(debug_text);
        drop(show_debug);
        drop(system);
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Debug UI
        let mut show_debug = self.show_debug.lock().unwrap();
        if *show_debug {
            egui::TopBottomPanel::bottom("debug_bottom")
                .exact_height(34.0)
                .frame(egui::Frame {
                    inner_margin: egui::style::Margin::same(8.0),
                    outer_margin: egui::style::Margin::same(0.0),
                    rounding: eframe::epaint::Rounding::none(),
                    shadow: eframe::epaint::Shadow::NONE,
                    fill: eframe::epaint::Color32::from_rgb(20, 20, 20),
                    stroke: eframe::epaint::Stroke::default(),
                })
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Copy to clipboard").clicked() {
                            let debug_text = self.debug_text.lock().unwrap();
                            ui.output().copied_text = (&*debug_text).to_string();
                            drop(debug_text);
                        }

                        if ui.button("Close").clicked() {
                            *show_debug = false;
                        }
                    })
                });

            egui::CentralPanel::default().show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut debug_text = self.debug_text.lock().unwrap();
                    ui.add(
                        TextEdit::multiline(&mut *debug_text)
                            .code_editor()
                            .desired_rows(4),
                    );
                    drop(debug_text);
                });
            });
            drop(show_debug);
            return;
        }
        drop(show_debug);

        // Main UI
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.with_layout(egui::Layout::left_to_right(egui::Align::TOP), |ui| {
                ui.heading(RichText::new("ROSE Title Changer").strong());
                ui.label(RichText::new("by Xikeon").small());

                ui.menu_button(RichText::new("⬇"), |ui| {
                    if ui.button("Debug").clicked() {
                        self.run_debug();
                        ui.close_menu();
                    }
                });
            });
            ui.add_space(10.0);

            let mut show_username = self.show_username.lock().unwrap();
            if ui
                .checkbox(&mut show_username, "Show character name")
                .changed()
            {
                drop(show_username);
                self.set_titles();
            } else {
                drop(show_username);
            }
            let mut show_job = self.show_job.lock().unwrap();
            if ui.checkbox(&mut show_job, "Show job").changed() {
                drop(show_job);
                self.set_titles();
            } else {
                drop(show_job);
            }
            ui.add_space(10.0);

            ui.label("Detected windows");
            ui.separator();

            use egui_extras::{Column, TableBuilder};
            TableBuilder::new(ui)
                .striped(true)
                .column(Column::auto().resizable(true).at_least(60.0))
                .column(Column::remainder())
                .header(24.0, |mut header| {
                    header.col(|ui| {
                        ui.label(RichText::new("pid").text_style(tableheading()).strong());
                    });
                    header.col(|ui| {
                        ui.label(RichText::new("title").text_style(tableheading()).strong());
                    });
                })
                .body(|body| {
                    let games = self.games.lock().unwrap();
                    let mut pids = games.keys();
                    let num_rows = pids.len();
                    body.rows(18.0, num_rows, |_row_index, mut row| {
                        let pid = pids.next().unwrap();
                        row.col(|ui| {
                            ui.label(games.get(pid).unwrap().pid.to_string());
                        });
                        row.col(|ui| {
                            ui.label(games.get(pid).unwrap().title.to_string());
                        });
                    });
                });
        });
    }
}
