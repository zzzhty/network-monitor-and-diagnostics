//! Pure startup decisions: no process, network, configuration, or GUI access.
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Prefer the CLI installed beside this binary (custom binDir included).
/// Explicit inputs keep tests independent of the user's PATH and HOME.
pub fn resolve_cli(
    executable: &Path,
    path: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    let sibling = executable
        .parent()?
        .join(if cfg!(windows) { "nmd.exe" } else { "nmd" });
    if sibling.is_file() {
        return Some(sibling);
    }
    if let Some(path) = path {
        for directory in std::env::split_paths(path).filter(|directory| directory.is_absolute()) {
            let candidate = directory.join(if cfg!(windows) { "nmd.exe" } else { "nmd" });
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    let fallback = PathBuf::from(home?).join(".local/bin/nmd");
    (fallback.is_absolute() && fallback.is_file()).then_some(fallback)
}

#[derive(Debug, PartialEq)]
pub enum ErrorNavigation {
    Page,
    Retry,
    Quit,
    Block,
}

/// Only our bundled page and two fixed actions are accepted. No remote links,
/// query parameters, fragments or user-supplied executable arguments.
pub fn error_navigation(url: &str) -> ErrorNavigation {
    match url {
        "tauri://localhost/desktop-error.html"
        | "http://tauri.localhost/desktop-error.html"
        | "https://tauri.localhost/desktop-error.html" => ErrorNavigation::Page,
        "nmd-startup://retry" | "nmd-startup://retry/" => ErrorNavigation::Retry,
        "nmd-startup://quit" | "nmd-startup://quit/" => ErrorNavigation::Quit,
        _ => ErrorNavigation::Block,
    }
}

pub fn error_title(message: &str) -> &'static str {
    match message.split(':').next().unwrap_or("") {
        "nmd_not_found" => "NMD · 未找到 CLI，请检查安装路径",
        "no_free_port" => "NMD · 本地端口不可用",
        "spawn_timeout" => "NMD · 本地面板启动超时",
        "child_exited" | "spawn_failed" => "NMD · CLI 启动失败",
        _ => "NMD · 本地面板不可用",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn error_page_allows_only_local_page_and_fixed_actions() {
        assert_eq!(
            error_navigation("tauri://localhost/desktop-error.html"),
            ErrorNavigation::Page
        );
        assert_eq!(
            error_navigation("http://tauri.localhost/desktop-error.html"),
            ErrorNavigation::Page
        );
        assert_eq!(
            error_navigation("nmd-startup://retry/"),
            ErrorNavigation::Retry
        );
        assert_eq!(
            error_navigation("nmd-startup://quit/"),
            ErrorNavigation::Quit
        );
        for url in [
            "https://example.invalid/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "nmd-startup://retry/?command=bad",
            "tauri://localhost/index.html",
            "http://tauri.localhost.evil/desktop-error.html",
        ] {
            assert_eq!(error_navigation(url), ErrorNavigation::Block);
        }
    }

    #[test]
    fn failure_title_never_reflects_untrusted_error_details() {
        assert_eq!(
            error_title("spawn_failed:<script>secret</script>"),
            "NMD · CLI 启动失败"
        );
        assert_eq!(error_title("unknown:secret"), "NMD · 本地面板不可用");
    }

    #[test]
    fn custom_bin_directory_sibling_wins_over_path_and_home() {
        // No tempfile crate is needed: this module can be tested offline alone.
        let root = std::env::temp_dir().join(format!("nmd-cli-{}", std::process::id()));
        let custom = root.join("custom-bin");
        let other = root.join("other-bin");
        let home = root.join("home");
        fs::create_dir_all(&custom).unwrap();
        fs::create_dir_all(&other).unwrap();
        fs::create_dir_all(home.join(".local/bin")).unwrap();
        let name = if cfg!(windows) { "nmd.exe" } else { "nmd" };
        let sibling = custom.join(name);
        fs::write(&sibling, "synthetic CLI, never executed").unwrap();
        fs::write(other.join(name), "synthetic PATH CLI").unwrap();
        fs::write(home.join(".local/bin/nmd"), "synthetic fallback CLI").unwrap();
        let path = std::env::join_paths([&other]).unwrap();
        let executable = custom.join("nmd-desktop");
        assert_eq!(
            resolve_cli(&executable, Some(&path), Some(home.as_os_str())),
            Some(sibling.clone())
        );
        fs::remove_file(sibling).unwrap();
        assert_eq!(
            resolve_cli(&executable, Some(&path), Some(home.as_os_str())),
            Some(other.join(name))
        );
        assert_eq!(
            resolve_cli(&executable, None, Some(home.as_os_str())),
            Some(home.join(".local/bin/nmd"))
        );
        assert_eq!(resolve_cli(&executable, None, None), None);
        fs::remove_dir_all(root).unwrap();
    }
}
