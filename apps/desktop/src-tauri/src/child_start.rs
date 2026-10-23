//! Owned child startup and cancellation, independent of HTTP and the GUI.
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Spawn and register under the ownership lock. Exit sets cancellation before
/// taking this lock, so it either prevents the spawn or reaps the registered
/// child before exit completes, even while readiness is blocked.
pub fn start_owned(
    executable: &Path,
    port: u16,
    owner: &Mutex<Option<Child>>,
    cancelled: &AtomicBool,
    ready: impl Fn(u16) -> bool,
) -> Result<u16, String> {
    {
        let mut child = owner.lock().unwrap();
        if cancelled.load(Ordering::SeqCst) {
            return Err("startup_cancelled".into());
        }
        *child = Some(
            Command::new(executable)
                .args(["gui", "--port", &port.to_string()])
                .stdin(Stdio::null())
                .spawn()
                .map_err(|error| format!("spawn_failed:{error}"))?,
        );
    }
    for _ in 0..40 {
        if cancelled.load(Ordering::SeqCst) {
            return Err("startup_cancelled".into());
        }
        let answered = ready(port);
        {
            let mut guard = owner.lock().unwrap();
            if cancelled.load(Ordering::SeqCst) || guard.is_none() {
                return Err("startup_cancelled".into());
            }
            let child = guard.as_mut().unwrap();
            if let Ok(Some(status)) = child.try_wait() {
                guard.take();
                return Err(format!("child_exited:{status}"));
            }
            if answered {
                return Ok(port);
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    reap_owned(owner);
    Err("spawn_timeout".into())
}

pub fn shutdown(child: &mut Child) {
    if child
        .try_wait()
        .map(|status| status.is_some())
        .unwrap_or(true)
    {
        return;
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The return value confirms an owned child was reaped, useful to the caller's
/// lifecycle regression; an external server is never present in this slot.
pub fn reap_owned(owner: &Mutex<Option<Child>>) -> bool {
    if let Some(mut child) = owner.lock().unwrap().take() {
        shutdown(&mut child);
        return child.try_wait().ok().flatten().is_some();
    }
    false
}

pub fn cancel(owner: &Mutex<Option<Child>>, cancelled: &AtomicBool) -> bool {
    cancelled.store(true, Ordering::SeqCst);
    reap_owned(owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_start_never_spawns_or_requires_an_executable() {
        let owner = Mutex::new(None);
        let cancelled = AtomicBool::new(true);
        let result = start_owned(
            Path::new("missing-fixture-cli"),
            1234,
            &owner,
            &cancelled,
            |_| panic!("readiness must not run after cancellation"),
        );
        assert_eq!(result.unwrap_err(), "startup_cancelled");
        assert!(owner.lock().unwrap().is_none());
        assert!(!cancel(&owner, &cancelled));
    }

    #[cfg(unix)]
    #[test]
    fn quit_during_delayed_readiness_reaps_before_the_worker_continues() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{mpsc, Arc};
        use std::time::{SystemTime, UNIX_EPOCH};

        for ready_answer in [false, true] {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory =
                std::env::temp_dir().join(format!("nmd-start-{}-{nonce}", std::process::id()));
            fs::create_dir(&directory).unwrap();
            let executable = directory.join("nmd-fixture");
            fs::write(&executable, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            let owner = Arc::new(Mutex::new(None));
            let cancelled = Arc::new(AtomicBool::new(false));
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let worker_owner = owner.clone();
            let worker_cancelled = cancelled.clone();
            let worker = std::thread::spawn(move || {
                start_owned(&executable, 1234, &worker_owner, &worker_cancelled, |_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    ready_answer
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let registered = owner.lock().unwrap().is_some();
            // Same cancellation path used by RunEvent::Exit. Readiness remains
            // blocked until after kill+wait, so worker Drop cannot hide a leak.
            let reaped = cancel(&owner, &cancelled);
            release_tx.send(()).unwrap();
            let result = worker.join().unwrap();
            fs::remove_dir_all(directory).unwrap();
            assert!(registered, "child must be owned before readiness starts");
            assert!(reaped, "quit must reap without waiting for readiness");
            assert_eq!(result.unwrap_err(), "startup_cancelled");
            assert!(owner.lock().unwrap().is_none());
        }
    }
}
