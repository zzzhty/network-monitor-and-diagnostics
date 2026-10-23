//! Sidecar lifecycle for `nmd gui`: fixed argv, no shell, own only what we spawn.
//!
//! An already-running dashboard is reused and never killed; the shell exits the
//! child it started when the application quits. The shell performs no other
//! writes: every dashboard mutation stays on the loopback HTTP path owned by
//! the Python backend.

use crate::http_probe;
use serde_json::Value;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

pub const PORT_RANGE_START: u16 = 8765;
pub const PORT_RANGE: u16 = 32;
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Readiness is defined by the dashboard's own machine contract: only the real
/// NMD dashboard (component field) counts, never an unrelated local service.
pub fn component_of(port: u16) -> Option<String> {
    let response = http_probe::get(port, "/api/capabilities", PROBE_TIMEOUT).ok()?;
    if response.status != 200 {
        return None;
    }
    let value: Value = serde_json::from_slice(&response.body).ok()?;
    value.get("component")?.as_str().map(str::to_owned)
}

pub fn find_existing_server() -> Option<u16> {
    (PORT_RANGE_START..PORT_RANGE_START + PORT_RANGE)
        .find(|&port| component_of(port).as_deref() == Some("nmd-observability"))
}

pub fn resolve_nmd() -> Option<PathBuf> {
    crate::startup::resolve_cli(
        &std::env::current_exe().ok()?,
        std::env::var_os("PATH").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

fn port_usable(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

pub enum Started {
    Reused(u16),
    Spawned { port: u16, child: Child },
}

/// Reuse an existing dashboard, else start one; readiness is the component probe.
/// The executable resolver is injectable so tests never start real processes.
pub fn ensure_server_with(resolver: impl Fn() -> Option<PathBuf>) -> Result<Started, String> {
    let owner = Mutex::new(None);
    let cancelled = AtomicBool::new(false);
    let (port, spawned) = ensure_owned_with(resolver, &owner, &cancelled)?;
    Ok(if spawned {
        let child = owner.lock().unwrap().take().unwrap();
        Started::Spawned { port, child }
    } else {
        Started::Reused(port)
    })
}

fn ensure_owned_with(
    resolver: impl Fn() -> Option<PathBuf>,
    owner: &Mutex<Option<Child>>,
    cancelled: &AtomicBool,
) -> Result<(u16, bool), String> {
    if cancelled.load(Ordering::SeqCst) {
        return Err("startup_cancelled".into());
    }
    if let Some(port) = find_existing_server() {
        return Ok((port, false));
    }
    let executable = resolver().ok_or("nmd_not_found")?;
    let port = (PORT_RANGE_START..PORT_RANGE_START + PORT_RANGE)
        .find(|&port| port_usable(port) && component_of(port).is_none())
        .ok_or("no_free_port")?;
    crate::child_start::start_owned(&executable, port, owner, cancelled, |port| {
        component_of(port).as_deref() == Some("nmd-observability")
    })?;
    Ok((port, true))
}

/// During retries/restarts, ownership stays in the app state through readiness
/// and the main-thread handoff, where Exit can always cancel and reap it.
pub fn ensure_server_owned(
    owner: &Mutex<Option<Child>>,
    cancelled: &AtomicBool,
) -> Result<u16, String> {
    ensure_owned_with(resolve_nmd, owner, cancelled).map(|(port, _)| port)
}

pub fn ensure_server() -> Result<Started, String> {
    ensure_server_with(resolve_nmd)
}

pub fn shutdown(child: &mut Child) {
    crate::child_start::shutdown(child);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::serve;
    use std::process::{Command, Stdio};
    #[cfg(unix)]
    use std::sync::Arc;

    #[test]
    fn component_probe_requires_nmd_contract() {
        let server = serve(|request| {
            assert!(request.starts_with("GET /api/capabilities "));
            (
                200,
                Some("{\"component\": \"nmd-observability\"}".to_string()),
            )
        });
        assert_eq!(
            component_of(server.port()).as_deref(),
            Some("nmd-observability")
        );
    }

    #[test]
    fn component_probe_passes_through_and_rejects_failures() {
        // The component string passes through; only the `nmd-observability`
        // comparison in find_existing_server/ensure_server grants reuse.
        let foreign = serve(|_| (200, Some("{\"component\": \"other\"}".to_string())));
        assert_eq!(component_of(foreign.port()).as_deref(), Some("other"));
        drop(foreign);
        let broken = serve(|_| (503, None));
        assert_eq!(component_of(broken.port()), None);
    }

    #[test]
    fn ensure_server_reports_missing_cli_deterministically() {
        match ensure_server_with(|| None) {
            Err(message) => assert_eq!(message, "nmd_not_found"),
            Ok(Started::Reused(port)) => {
                // A real dashboard was already listening in the shell port
                // range; reuse is the correct outcome there too.
                assert_eq!(component_of(port).as_deref(), Some("nmd-observability"));
            }
            Ok(Started::Spawned { .. }) => panic!("must never spawn with an unresolvable nmd"),
        }
    }

    #[test]
    fn resolve_nmd_returns_absolute_existing_file_or_none() {
        if let Some(path) = resolve_nmd() {
            assert!(path.is_absolute());
            assert!(path.is_file());
        }
    }

    #[test]
    fn port_probe_never_selects_a_foreign_listener_port() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        // The contract ensure_server relies on: a held port cannot be bound
        // again. Whether the OS hands the port back right after drop is up to
        // the scheduler (parallel tests open sockets), so we never assert that.
        assert!(!port_usable(port));
    }

    #[test]
    fn shutdown_is_idempotent_on_exited_children() {
        let mut child = noop_child();
        let _ = child.wait();
        shutdown(&mut child);
    }

    /// A command that exits immediately, on every supported platform.
    fn noop_child() -> Child {
        #[cfg(unix)]
        let mut command = Command::new("true");
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("cmd");
            command.args(["/C", "exit", "0"]);
            command
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn spawn_failure_surfaces_as_fixed_error() {
        // A resolver pointing at a non-executable file fails at spawn time.
        let blocker: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        let fake = std::env::temp_dir().join(format!("nmd-not-exec-{}", std::process::id()));
        std::fs::write(&fake, b"not executable").unwrap();
        let result = ensure_server_with(|| Some(fake.clone()));
        match result {
            Err(message) => assert!(message.starts_with("spawn_failed"), "{message}"),
            Ok(Started::Reused(_)) => {}
            Ok(_) => panic!("must not spawn"),
        }
        drop(blocker);
        let _ = std::fs::remove_file(&fake);
    }
}
