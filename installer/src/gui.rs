use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use gtk::prelude::*;

use crate::ops::{
    detect_environment, launch_installed_app, run_install, run_uninstall, InstallConfig,
    InstallMode, ProgressMsg,
};

const ICON_BYTES: &[u8] = include_bytes!("../../tauri-app/src-tauri/icons/icon.png");

const INSTALLER_CSS: &str = r#"
window, .aegis-root {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: "Inter", "Segoe UI", "Ubuntu", sans-serif;
}
.aegis-card {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 14px;
}
.aegis-title {
    font-size: 18px;
    font-weight: 700;
    color: #f0f6fc;
}
.aegis-sub {
    font-size: 12px;
    color: #8b949e;
}
.aegis-section-label {
    font-size: 11px;
    font-weight: 700;
    color: #58a6ff;
    letter-spacing: 0.5px;
}
.aegis-badge-ok {
    background-color: #0f2e22;
    color: #3fb950;
    border: 1px solid #238636;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}
.aegis-badge-warn {
    background-color: #2c2208;
    color: #d29922;
    border: 1px solid #9e6a03;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}
entry {
    background-color: #0d1117;
    color: #f0f6fc;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 10px;
}
progressbar trough {
    background-color: #21262d;
    border-radius: 6px;
    min-height: 10px;
}
progressbar progress {
    background-color: #10b981;
    border-radius: 6px;
    min-height: 10px;
}
textview, textview text {
    background-color: #090d12;
    color: #c9d1d9;
    font-family: "JetBrains Mono", "Consolas", "Liberation Mono", monospace;
    font-size: 11px;
}
button.aegis-primary {
    background-image: none;
    background-color: #10b981;
    color: #04130d;
    border: 1px solid #34d399;
    border-radius: 6px;
    font-weight: 700;
    padding: 8px 16px;
}
button.aegis-primary:hover {
    background-color: #34d399;
}
button.aegis-launch {
    background-image: none;
    background-color: #2563eb;
    color: #ffffff;
    border: 1px solid #3b82f6;
    border-radius: 6px;
    font-weight: 700;
    padding: 8px 16px;
}
button.aegis-secondary {
    background-image: none;
    background-color: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 7px 14px;
}
button.aegis-danger {
    background-image: none;
    background-color: #3b1219;
    color: #f87171;
    border: 1px solid #7f1d1d;
    border-radius: 6px;
    padding: 7px 14px;
}
"#;

pub fn run_gui(default_mode: InstallMode) -> anyhow::Result<()> {
    let app = gtk::Application::builder()
        .application_id("io.aegisguard.installer")
        .build();

    app.connect_activate(move |gtk_app| {
        build_installer_window(gtk_app, default_mode);
    });

    app.run_with_args::<&str>(&[]);
    Ok(())
}

fn load_icon_pixbuf(size: i32) -> Option<gdk_pixbuf::Pixbuf> {
    let loader = gdk_pixbuf::PixbufLoader::new();
    loader.write(ICON_BYTES).ok()?;
    loader.close().ok()?;
    let pb = loader.pixbuf()?;
    if size > 0 {
        pb.scale_simple(size, size, gdk_pixbuf::InterpType::Bilinear)
    } else {
        Some(pb)
    }
}

fn make_badge(label_text: &str, ok: bool) -> gtk::Label {
    let lbl = gtk::Label::new(Some(label_text));
    lbl.style_context()
        .add_class(if ok { "aegis-badge-ok" } else { "aegis-badge-warn" });
    lbl
}

fn build_installer_window(app: &gtk::Application, default_mode: InstallMode) {
    let env_info = detect_environment();

    let provider = gtk::CssProvider::new();
    if provider.load_from_data(INSTALLER_CSS.as_bytes()).is_ok() {
        if let Some(screen) = gtk::gdk::Screen::default() {
            gtk::StyleContext::add_provider_for_screen(
                &screen,
                &provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    }

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("Aegis-Guard v1.2.0 — Cross-Platform Installer")
        .default_width(760)
        .default_height(640)
        .resizable(true)
        .build();

    if let Some(pb) = load_icon_pixbuf(128) {
        window.set_icon(Some(&pb));
    }

    let root = gtk::Box::new(gtk::Orientation::Vertical, 12);
    root.style_context().add_class("aegis-root");
    root.set_margin_top(16);
    root.set_margin_bottom(16);
    root.set_margin_start(18);
    root.set_margin_end(18);

    // ── Header ───────────────────────────────────────────────────────────────
    let header_card = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    header_card.style_context().add_class("aegis-card");

    if let Some(pb) = load_icon_pixbuf(44) {
        let img = gtk::Image::from_pixbuf(Some(&pb));
        header_card.pack_start(&img, false, false, 0);
    }

    let title_box = gtk::Box::new(gtk::Orientation::Vertical, 3);
    let title_lbl = gtk::Label::new(Some("Aegis-Guard Setup (v1.2.0)"));
    title_lbl.set_xalign(0.0);
    title_lbl.style_context().add_class("aegis-title");

    let priv_text = if env_info.is_elevated {
        "Administrator / Root"
    } else {
        "Standard User (Writable Prefix)"
    };
    let sub_lbl = gtk::Label::new(Some(&format!(
        "Target Host: {} ({}) • Privileges: {} • Engine: Rust + Go + React",
        env_info.os.to_uppercase(),
        env_info.arch,
        priv_text
    )));
    sub_lbl.set_xalign(0.0);
    sub_lbl.style_context().add_class("aegis-sub");

    title_box.pack_start(&title_lbl, false, false, 0);
    title_box.pack_start(&sub_lbl, false, false, 0);
    header_card.pack_start(&title_box, true, true, 0);
    root.pack_start(&header_card, false, false, 0);

    // ── Toolchain Badges ─────────────────────────────────────────────────────
    let badge_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    badge_row.pack_start(
        &make_badge(
            if env_info.has_node {
                &format!("Node {}", env_info.node_version)
            } else {
                "Node.js Missing (Required)"
            },
            env_info.has_node,
        ),
        false,
        false,
        0,
    );
    badge_row.pack_start(
        &make_badge(
            if env_info.has_cargo {
                "Rust / Cargo Ready"
            } else {
                "Rust Absent (Console Mode)"
            },
            env_info.has_cargo,
        ),
        false,
        false,
        0,
    );
    badge_row.pack_start(
        &make_badge(
            if env_info.has_go {
                "Go Observer Ready"
            } else {
                "Go Optional"
            },
            env_info.has_go,
        ),
        false,
        false,
        0,
    );
    badge_row.pack_start(
        &make_badge(
            if env_info.local_repo.is_some() {
                "Local Repo Detected"
            } else {
                "Remote GitHub Clone"
            },
            true,
        ),
        false,
        false,
        0,
    );
    root.pack_start(&badge_row, false, false, 0);

    // ── Installation Profile & Options Card ──────────────────────────────────
    let opts_card = gtk::Box::new(gtk::Orientation::Vertical, 10);
    opts_card.style_context().add_class("aegis-card");

    let mode_hdr = gtk::Label::new(Some("INSTALLATION PROFILE"));
    mode_hdr.set_xalign(0.0);
    mode_hdr.style_context().add_class("aegis-section-label");
    opts_card.pack_start(&mode_hdr, false, false, 0);

    let radio_desktop = gtk::RadioButton::with_label(
        "Full Desktop Suite + Kernel Engines (Native Desktop Window + Process Engine + Go IDS)",
    );
    let radio_console = gtk::RadioButton::with_label_from_widget(
        &radio_desktop,
        "Web & Console Server Mode (Express + SSE UI on http://127.0.0.1:3000 + CLI 'aegis-guard')",
    );
    if default_mode == InstallMode::Console || !env_info.has_cargo {
        radio_console.set_active(true);
    } else {
        radio_desktop.set_active(true);
    }
    opts_card.pack_start(&radio_desktop, false, false, 0);
    opts_card.pack_start(&radio_console, false, false, 0);

    let path_hdr = gtk::Label::new(Some("INSTALL DIRECTORY"));
    path_hdr.set_xalign(0.0);
    path_hdr.set_margin_top(4);
    path_hdr.style_context().add_class("aegis-section-label");
    opts_card.pack_start(&path_hdr, false, false, 0);

    let path_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let dir_entry = gtk::Entry::new();
    dir_entry.set_text(&env_info.default_install_dir.to_string_lossy());
    let browse_btn = gtk::Button::with_label("Browse…");
    browse_btn.style_context().add_class("aegis-secondary");

    let win_ref = window.clone();
    let dir_entry_browse = dir_entry.clone();
    browse_btn.connect_clicked(move |_| {
        let dialog = gtk::FileChooserDialog::with_buttons(
            Some("Choose Aegis-Guard Install Directory"),
            Some(&win_ref),
            gtk::FileChooserAction::SelectFolder,
            &[("Cancel", gtk::ResponseType::Cancel), ("Select", gtk::ResponseType::Accept)],
        );
        if dialog.run() == gtk::ResponseType::Accept {
            if let Some(folder) = dialog.filename() {
                dir_entry_browse.set_text(&folder.to_string_lossy());
            }
        }
        dialog.close();
    });

    path_row.pack_start(&dir_entry, true, true, 0);
    path_row.pack_start(&browse_btn, false, false, 0);
    opts_card.pack_start(&path_row, false, false, 0);

    let chk_row = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    let chk_shortcuts = gtk::CheckButton::with_label("Create Desktop & Application Menu Shortcuts");
    chk_shortcuts.set_active(true);
    let chk_services = gtk::CheckButton::with_label("Configure Daemons & Firewall Rules (when elevated)");
    chk_services.set_active(env_info.is_elevated);
    chk_row.pack_start(&chk_shortcuts, false, false, 0);
    chk_row.pack_start(&chk_services, false, false, 0);
    opts_card.pack_start(&chk_row, false, false, 0);

    root.pack_start(&opts_card, false, false, 0);

    // ── Progress & Live Output Log ───────────────────────────────────────────
    let prog_card = gtk::Box::new(gtk::Orientation::Vertical, 8);
    prog_card.style_context().add_class("aegis-card");

    let step_label = gtk::Label::new(Some("Ready to install Aegis-Guard."));
    step_label.set_xalign(0.0);
    let progress_bar = gtk::ProgressBar::new();
    progress_bar.set_fraction(0.0);
    progress_bar.set_show_text(true);
    progress_bar.set_text(Some("0%"));

    let log_view = gtk::TextView::new();
    log_view.set_editable(false);
    log_view.set_cursor_visible(false);
    log_view.set_wrap_mode(gtk::WrapMode::WordChar);
    if let Some(buf) = log_view.buffer() {
        buf.set_text("Welcome to Aegis-Guard v1.2.0 Cross-Platform GTK Installer.\nClick 'Install Aegis-Guard' to build, configure shortcuts, and verify binaries.\n");
    }

    let scroller = gtk::ScrolledWindow::builder()
        .min_content_height(200)
        .vexpand(true)
        .hexpand(true)
        .build();
    scroller.add(&log_view);

    prog_card.pack_start(&step_label, false, false, 0);
    prog_card.pack_start(&progress_bar, false, false, 0);
    prog_card.pack_start(&scroller, true, true, 0);
    root.pack_start(&prog_card, true, true, 0);

    // ── Bottom Action Bar ────────────────────────────────────────────────────
    let btn_row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let uninstall_btn = gtk::Button::with_label("Uninstall");
    uninstall_btn.style_context().add_class("aegis-danger");

    let quit_btn = gtk::Button::with_label("Close");
    quit_btn.style_context().add_class("aegis-secondary");

    let launch_btn = gtk::Button::with_label("Launch Aegis-Guard");
    launch_btn.style_context().add_class("aegis-launch");
    launch_btn.set_sensitive(false);

    let install_btn = gtk::Button::with_label("Install Aegis-Guard");
    install_btn.style_context().add_class("aegis-primary");

    btn_row.pack_start(&uninstall_btn, false, false, 0);
    btn_row.pack_end(&install_btn, false, false, 0);
    btn_row.pack_end(&launch_btn, false, false, 0);
    btn_row.pack_end(&quit_btn, false, false, 0);
    root.pack_start(&btn_row, false, false, 0);

    window.add(&root);

    let launch_target_holder: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));

    let app_quit = app.clone();
    quit_btn.connect_clicked(move |_| {
        app_quit.quit();
    });

    // Launch handler
    {
        let lt_ref = launch_target_holder.clone();
        let de_ref = dir_entry.clone();
        launch_btn.connect_clicked(move |_| {
            let dir = PathBuf::from(de_ref.text().as_str());
            launch_installed_app(lt_ref.borrow().clone(), &dir);
        });
    }

    // Install handler
    {
        let install_btn_c = install_btn.clone();
        let uninstall_btn_c = uninstall_btn.clone();
        let launch_btn_c = launch_btn.clone();
        let step_label_c = step_label.clone();
        let progress_c = progress_bar.clone();
        let log_view_c = log_view.clone();
        let dir_entry_c = dir_entry.clone();
        let radio_desktop_c = radio_desktop.clone();
        let chk_shortcuts_c = chk_shortcuts.clone();
        let chk_services_c = chk_services.clone();
        let lt_holder = launch_target_holder.clone();

        install_btn.connect_clicked(move |_| {
            install_btn_c.set_sensitive(false);
            uninstall_btn_c.set_sensitive(false);
            launch_btn_c.set_sensitive(false);
            progress_c.set_fraction(0.05);
            progress_c.set_text(Some("Starting…"));

            let cfg = InstallConfig {
                mode: if radio_desktop_c.is_active() {
                    InstallMode::Desktop
                } else {
                    InstallMode::Console
                },
                install_dir: PathBuf::from(dir_entry_c.text().as_str()),
                create_shortcuts: chk_shortcuts_c.is_active(),
                setup_services: chk_services_c.is_active(),
                configure_firewall: chk_services_c.is_active(),
            };

            let (tx, rx) = mpsc::channel::<ProgressMsg>();
            std::thread::spawn(move || run_install(cfg, tx));

            let ib = install_btn_c.clone();
            let ub = uninstall_btn_c.clone();
            let lb = launch_btn_c.clone();
            let sl = step_label_c.clone();
            let pb = progress_c.clone();
            let lv = log_view_c.clone();
            let lh = lt_holder.clone();

            glib::timeout_add_local(Duration::from_millis(60), move || {
                while let Ok(msg) = rx.try_recv() {
                    match msg {
                        ProgressMsg::Step { index, total, title } => {
                            let frac = (index as f64) / (total as f64 + 0.5);
                            pb.set_fraction(frac.min(0.95));
                            pb.set_text(Some(&format!("{}%", (frac * 100.0).round() as u32)));
                            sl.set_text(&format!("Step {}/{}: {}", index, total, title));
                        }
                        ProgressMsg::Log(line) => {
                            append_log(&lv, &line);
                        }
                        ProgressMsg::Finished {
                            success,
                            summary,
                            launch_target,
                        } => {
                            pb.set_fraction(if success { 1.0 } else { 0.0 });
                            pb.set_text(Some(if success { "100% — Complete" } else { "Failed" }));
                            sl.set_text(&summary);
                            append_log(&lv, &format!("\n{}", summary));
                            *lh.borrow_mut() = launch_target;
                            ib.set_sensitive(true);
                            ub.set_sensitive(true);
                            lb.set_sensitive(success);
                            return glib::ControlFlow::Break;
                        }
                    }
                }
                glib::ControlFlow::Continue
            });
        });
    }

    // Uninstall handler
    {
        let install_btn_c = install_btn.clone();
        let uninstall_btn_c = uninstall_btn.clone();
        let launch_btn_c = launch_btn.clone();
        let step_label_c = step_label.clone();
        let progress_c = progress_bar.clone();
        let log_view_c = log_view.clone();
        let dir_entry_c = dir_entry.clone();

        uninstall_btn.connect_clicked(move |_| {
            install_btn_c.set_sensitive(false);
            uninstall_btn_c.set_sensitive(false);
            launch_btn_c.set_sensitive(false);
            let dir = PathBuf::from(dir_entry_c.text().as_str());
            let (tx, rx) = mpsc::channel::<ProgressMsg>();
            std::thread::spawn(move || run_uninstall(dir, tx));

            let ib = install_btn_c.clone();
            let ub = uninstall_btn_c.clone();
            let sl = step_label_c.clone();
            let pb = progress_c.clone();
            let lv = log_view_c.clone();

            glib::timeout_add_local(Duration::from_millis(60), move || {
                while let Ok(msg) = rx.try_recv() {
                    match msg {
                        ProgressMsg::Step { index, total, title } => {
                            pb.set_fraction(index as f64 / total as f64);
                            sl.set_text(&format!("Step {}/{}: {}", index, total, title));
                        }
                        ProgressMsg::Log(line) => append_log(&lv, &line),
                        ProgressMsg::Finished { summary, .. } => {
                            pb.set_fraction(1.0);
                            pb.set_text(Some("Removed"));
                            sl.set_text(&summary);
                            ib.set_sensitive(true);
                            ub.set_sensitive(true);
                            return glib::ControlFlow::Break;
                        }
                    }
                }
                glib::ControlFlow::Continue
            });
        });
    }

    window.show_all();
}

fn append_log(tv: &gtk::TextView, line: &str) {
    if let Some(buf) = tv.buffer() {
        let mut end = buf.end_iter();
        buf.insert(&mut end, line);
        buf.insert(&mut end, "\n");
        if let Some(mark) = buf.create_mark(None, &buf.end_iter(), false) {
            tv.scroll_to_mark(&mark, 0.0, false, 0.0, 1.0);
            buf.delete_mark(&mark);
        }
    }
}
