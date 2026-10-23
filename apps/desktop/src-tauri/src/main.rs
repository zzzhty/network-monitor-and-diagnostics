//! NMD desktop shell: a thin Tauri window over the local Python dashboard.
//!
//! The shell is a read-only consumer plus the lifecycle owner of the `nmd gui`
//! child it started. All egress mutations stay on the loopback HTTP path owned
//! by the Python backend; nothing here re-implements dashboard logic.

mod child_start;
mod http_probe;
mod poller;
mod shell;
mod startup;
#[cfg(test)]
mod test_support;

use poller::Notifier;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_notification::NotificationExt;

struct ShellState {
    child: Arc<Mutex<Option<std::process::Child>>>,
    stopping: Arc<AtomicBool>,
    tray: Mutex<Option<tauri::tray::TrayIcon>>,
    retrying: AtomicBool,
}

const POLL_INTERVAL: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// A dead child we own is restarted after this many consecutive dead polls.
const RESTART_AFTER_TICKS: u32 = 6;

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn solid_tray_icon() -> tauri::image::Image<'static> {
    // 16x16 accent square; a real icon asset can replace this later.
    let mut rgba = Vec::with_capacity(16 * 16 * 4);
    for y in 0..16u8 {
        for x in 0..16u8 {
            let border = !(2..=13).contains(&x) || !(2..=13).contains(&y);
            let (r, g, b, a) = if border {
                (0x26, 0x30, 0x43, 0xff)
            } else {
                (0xa8, 0xbb, 0xff, 0xff)
            };
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }
    tauri::image::Image::new_owned(rgba, 16, 16)
}

fn tray_tooltip(app: &AppHandle, text: &str) {
    let handle = app.clone();
    let text = text.to_string();
    let _ = app.run_on_main_thread(move || {
        let tray = handle.state::<ShellState>().tray.lock().unwrap().clone();
        if let Some(tray) = tray {
            let _ = tray.set_tooltip(Some(&text));
        }
    });
}

fn notify(app: &AppHandle, body: &str) {
    let _ = app.notification().builder().title("NMD").body(body).show();
}

/// One read-only cycle: notifications from the snapshot, tooltip from sources.
/// Returns whether the server answered both probes.
fn poll_tick(app: &AppHandle, port: u16, notifier: &mut Notifier) -> bool {
    let mut answered = true;
    match http_probe::get(port, "/api/snapshot", REQUEST_TIMEOUT) {
        Ok(response) if response.status == 200 => {
            if let Ok(value) = serde_json::from_slice::<Value>(&response.body) {
                for message in notifier.absorb(&value) {
                    notify(app, &message);
                }
            } else {
                answered = false;
            }
        }
        _ => answered = false,
    }
    match http_probe::get(port, "/api/sources", REQUEST_TIMEOUT) {
        Ok(response) if response.status == 200 => {
            if let Ok(value) = serde_json::from_slice::<Value>(&response.body) {
                let label = poller::egress_label(&value).unwrap_or_else(|| "未知".into());
                tray_tooltip(app, &format!("NMD · 出口:{label}"));
            } else {
                answered = false;
            }
        }
        _ => answered = false,
    }
    if !answered {
        tray_tooltip(app, "NMD · 出口:未知");
    }
    answered
}

/// Restart only a child we own; an externally started server is left alone.
fn restart_if_owned(app: &AppHandle) -> Option<u16> {
    let state = app.state::<ShellState>();
    let exited = {
        let mut guard = state.child.lock().unwrap();
        match guard.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            None => false,
        }
    };
    if !exited {
        return None;
    }
    state.child.lock().unwrap().take(); // already reaped by try_wait above
    shell::ensure_server_owned(&state.child, &state.stopping).ok()
}

fn poll_loop(app: AppHandle, mut port: u16) {
    let mut notifier = Notifier::new(unix_now());
    let mut failures = 0u32;
    loop {
        std::thread::sleep(POLL_INTERVAL);
        if poll_tick(&app, port, &mut notifier) {
            failures = 0;
            continue;
        }
        failures += 1;
        if failures >= RESTART_AFTER_TICKS {
            if let Some(fresh) = restart_if_owned(&app) {
                port = fresh;
                failures = 0;
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.eval(format!("location.href = 'http://127.0.0.1:{port}/'"));
                }
            }
        }
    }
}

/// SIGTERM/SIGINT must reach the normal exit path so the child we started is
/// shut down; a default signal death would leak the dashboard process. The
/// iterator API is Unix-only; Windows exits via the console/window close path.
#[cfg(unix)]
fn install_signal_exit(handle: tauri::AppHandle) {
    std::thread::spawn(move || {
        let mut terms = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGINT,
        ])
        .expect("signal registration");
        for _ in terms.forever() {
            handle.exit(0);
        }
    });
}

#[cfg(not(unix))]
fn install_signal_exit(_handle: tauri::AppHandle) {}

fn shutdown_owned(app: &AppHandle) {
    if let Some(mut child) = app.state::<ShellState>().child.lock().unwrap().take() {
        shell::shutdown(&mut child);
    }
}

fn open_dashboard(app: &AppHandle, started: shell::Started) -> tauri::Result<()> {
    let port = match started {
        shell::Started::Spawned { port, child } => {
            *app.state::<ShellState>().child.lock().unwrap() = Some(child);
            port
        }
        shell::Started::Reused(port) => port,
    };
    let result = (|| {
        let url = format!("http://127.0.0.1:{port}/")
            .parse()
            .expect("loopback url");
        WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
            .title("NMD · 网络观察台")
            .inner_size(1100.0, 780.0)
            .min_inner_size(580.0, 420.0)
            .build()?;
        let toggle = MenuItem::with_id(app, "toggle", "显示 / 隐藏", true, None::<&str>)?;
        let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
        let menu = Menu::with_items(app, &[&toggle, &quit])?;
        let tray = TrayIconBuilder::new()
            .icon(solid_tray_icon())
            .tooltip("NMD · 出口:未知")
            .menu(&menu)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| match event.id().as_ref() {
                "toggle" => {
                    if let Some(window) = app.get_webview_window("main") {
                        if window.is_visible().unwrap_or(false) {
                            let _ = window.hide();
                        } else {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                }
                "quit" => app.exit(0),
                _ => {}
            })
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    let app = tray.app_handle();
                    if let Some(window) = app.get_webview_window("main") {
                        if window.is_visible().unwrap_or(false) {
                            let _ = window.hide();
                        } else {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                }
            })
            .build(app)?;
        *app.state::<ShellState>().tray.lock().unwrap() = Some(tray);
        let handle = app.clone();
        std::thread::spawn(move || poll_loop(handle, port));
        Ok(())
    })();
    if result.is_err() {
        shutdown_owned(app);
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.destroy();
        }
    }
    result
}

/// Reap our child if the app exits before the main-thread callback can run.
struct PendingStart(Option<shell::Started>);

impl Drop for PendingStart {
    fn drop(&mut self) {
        if let Some(shell::Started::Spawned { child, .. }) = self.0.as_mut() {
            shell::shutdown(child);
        }
    }
}

fn retry_startup(app: &AppHandle) {
    if app
        .state::<ShellState>()
        .retrying
        .swap(true, Ordering::SeqCst)
    {
        return;
    }
    let background = app.clone();
    let owner = app.state::<ShellState>().child.clone();
    let cancelled = app.state::<ShellState>().stopping.clone();
    std::thread::spawn(move || {
        let result = shell::ensure_server_owned(&owner, &cancelled);
        let handle = background.clone();
        let _ = background.run_on_main_thread(move || {
            if handle.state::<ShellState>().stopping.load(Ordering::SeqCst) {
                return;
            }
            let failure = match result {
                Ok(port) => match open_dashboard(&handle, shell::Started::Reused(port)) {
                    Ok(()) => {
                        if let Some(window) = handle.get_webview_window("startup-error") {
                            let _ = window.destroy();
                        }
                        None
                    }
                    Err(_) => Some("window_failed".to_string()),
                },
                Err(message) => Some(message),
            };
            if let Some(message) = failure {
                let _ = show_startup_error(&handle, &message);
            }
            handle
                .state::<ShellState>()
                .retrying
                .store(false, Ordering::SeqCst);
        });
    });
}

fn show_startup_error(app: &AppHandle, message: &str) -> tauri::Result<()> {
    let title = startup::error_title(message);
    if let Some(window) = app.get_webview_window("startup-error") {
        window.set_title(title)?;
        window.show()?;
        return Ok(());
    }
    let handle = app.clone();
    WebviewWindowBuilder::new(
        app,
        "startup-error",
        WebviewUrl::App("desktop-error.html".into()),
    )
    .title(title)
    .inner_size(700.0, 460.0)
    .on_navigation(move |url| match startup::error_navigation(url.as_str()) {
        startup::ErrorNavigation::Page => true,
        startup::ErrorNavigation::Retry => {
            retry_startup(&handle);
            false
        }
        startup::ErrorNavigation::Quit => {
            handle.exit(0);
            false
        }
        startup::ErrorNavigation::Block => false,
    })
    .build()?;
    Ok(())
}

fn main() {
    let preflight = shell::ensure_server().map(|started| PendingStart(Some(started)));
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(move |app| {
            app.manage(ShellState {
                child: Arc::new(Mutex::new(None)),
                stopping: Arc::new(AtomicBool::new(false)),
                tray: Mutex::new(None),
                retrying: AtomicBool::new(false),
            });
            match preflight {
                Ok(mut pending) => {
                    if open_dashboard(app.handle(), pending.0.take().unwrap()).is_err() {
                        show_startup_error(app.handle(), "window_failed")?;
                    }
                }
                Err(message) => show_startup_error(app.handle(), &message)?,
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("tauri build");
    install_signal_exit(app.handle().clone());
    app.run(|app, event| {
        if let RunEvent::Exit = event {
            let state = app.state::<ShellState>();
            child_start::cancel(&state.child, &state.stopping);
        }
    });
}
