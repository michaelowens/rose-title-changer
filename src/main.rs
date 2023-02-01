#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use core::time;
use eframe::egui::{self, RichText, TextEdit, TextStyle};
use eframe::epaint::{FontFamily, FontId};
use eframe::Theme;
use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use tray_item::TrayItem;
use windows_api::load_app_icon;

mod helpers;
mod process_memory;
mod windows_api;
use crate::helpers::*;

fn main() {
    let icon_data = load_app_icon();
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(320.0, 240.0)),
        resizable: false,
        follow_system_theme: false,
        default_theme: Theme::Dark,
        icon_data: Some(icon_data),
        ..Default::default()
    };
    eframe::run_native(
        "ROSE Title Changer",
        options.clone(),
        Box::new(|cc| {
            let mut app = MyApp::new(cc);
            app.init_tray(&cc.egui_ctx);
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
    window_handle: Option<usize>,
    title: String,
}

enum TrayMessage {
    Show,
    Quit,
}

#[derive(Clone)]
struct MyApp {
    app_is_hidden: Arc<Mutex<bool>>,
    new_hidden_state: Arc<Mutex<bool>>,
    quit_app: Arc<Mutex<bool>>,
    show_username: Arc<Mutex<bool>>,
    show_job: Arc<Mutex<bool>>,
    system: Arc<Mutex<System>>,
    games: Arc<Mutex<HashMap<u32, Game>>>,
    show_debug: Arc<Mutex<bool>>,
    debug_text: Arc<Mutex<String>>,
    signature: Arc<Mutex<String>>,
}

impl MyApp {
    fn new(cc: &eframe::CreationContext) -> Self {
        configure_text_styles(&cc.egui_ctx);
        // TODO: find a better way than wrapping everything in Arc/Mutex
        Self {
            app_is_hidden: Arc::new(Mutex::new(false)),
            new_hidden_state: Arc::new(Mutex::new(false)),
            quit_app: Arc::new(Mutex::new(false)),
            show_username: Arc::new(Mutex::new(true)),
            show_job: Arc::new(Mutex::new(true)),
            system: Arc::new(Mutex::new(sysinfo::System::new())),
            games: Arc::new(Mutex::new(HashMap::new())),
            show_debug: Arc::new(Mutex::new(false)),
            debug_text: Arc::new(Mutex::new("".into())),
            signature: Arc::new(Mutex::new("? 83 EC 28 ? 8B 05 ? ? ? ? ? 85 C0 ? 24 ? 38 6B 00 00 ? ? ? ? ? ? 89 44 24 30 ? 85 C0".into())),
        }
    }

    fn init_tray(&mut self, ectx: &egui::Context) {
        let me = self.clone();
        let ctx = ectx.clone();
        thread::spawn(move || loop {
            let mut tray = TrayItem::new("ROSE Title Changer", "tray-icon").unwrap();

            let (tx, rx) = mpsc::channel();

            {
                let tx = tx.clone();
                tray.add_menu_item("Show", move || tx.send(TrayMessage::Show).unwrap())
                    .unwrap();
            }
            {
                let tx = tx.clone();
                tray.add_menu_item("Quit", move || tx.send(TrayMessage::Quit).unwrap())
                    .unwrap();
            }

            loop {
                match rx.recv() {
                    Ok(TrayMessage::Show) => *me.new_hidden_state.lock().unwrap() = false,
                    Ok(TrayMessage::Quit) => *me.quit_app.lock().unwrap() = true,
                    _ => {}
                }
                ctx.request_repaint()
            }
        });
    }

    fn start_timer(&mut self, ectx: &egui::Context) {
        let mut me = self.clone();
        let ctx = ectx.clone();
        thread::spawn(move || loop {
            me.find_games();
            me.set_titles();
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
                let signature = self.signature.lock().unwrap();
                signature_address =
                    sig_scan(&process, &(*signature), base_address, module_end).unwrap_or(0);
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

            let window_handle = find_process_window(process.pid);

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

            {
                let show_username = self.show_username.lock().unwrap();
                let show_job = self.show_job.lock().unwrap();
                if *show_username {
                    title_parts.push(player_name);
                }

                if *show_job {
                    title_parts.push(job_id_to_name(player_job_id));
                }
            }

            game.title = title_parts.join(" - ");

            if let Some(window_handle) = game.window_handle {
                windows_api::window_set_title(window_handle, &game.title);
            }
        }
    }

    fn run_debug(&mut self) {
        let mut show_debug = self.show_debug.lock().unwrap();
        let mut debug_text = self.debug_text.lock().unwrap();
        *debug_text = get_debug_info(&(*self.signature.lock().unwrap()));
        *show_debug = true;
    }
}

impl eframe::App for MyApp {
    fn on_close_event(&mut self) -> bool {
        let mut new_hidden_state = self.new_hidden_state.lock().unwrap();
        *new_hidden_state = true;
        *self.quit_app.lock().unwrap()
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Quit app
        {
            let quit_app = self.quit_app.lock().unwrap();
            if *quit_app {
                frame.close();
                return;
            }
        }
        // Hidden in tray
        {
            let mut app_is_hidden = self.app_is_hidden.lock().unwrap();
            let new_hidden_state = self.new_hidden_state.lock().unwrap();
            if *new_hidden_state != *app_is_hidden {
                *app_is_hidden = *new_hidden_state;
                let mut is_visible = true;
                if *app_is_hidden {
                    is_visible = false;
                }
                frame.set_visible(is_visible);
            }

            if *app_is_hidden {
                return;
            }
        }

        // Debug UI
        {
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
                return;
            }
        }

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

            /*{
                let mut signature = self.signature.lock().unwrap();
                ui.text_edit_singleline(&mut *signature);
            }*/

            {
                let mut show_username = self.show_username.lock().unwrap();
                if ui
                    .checkbox(&mut show_username, "Show character name")
                    .changed()
                {
                    drop(show_username);
                    self.set_titles();
                }
            }

            {
                let mut show_job = self.show_job.lock().unwrap();
                if ui.checkbox(&mut show_job, "Show job").changed() {
                    drop(show_job);
                    self.set_titles();
                }
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
