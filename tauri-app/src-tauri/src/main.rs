#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(target_os = "linux")]
    {
        // Prevent WebKitGTK DMABUF / GBM rendering crashes and blank windows on Wayland,
        // hybrid GPU setups, and virtualized displays unless explicitly overridden.
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none()
            && std::env::var_os("AEGIS_KEEP_DMABUF").is_none()
        {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }

    aegis_tauri_lib::run();
}
