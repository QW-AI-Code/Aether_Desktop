//! Opening a config file WITH Aether: double-click, right-click → "Open with",
//! or a file dropped on `Aether.exe` / its shortcut (1.5.0, same version).
//!
//! # The bug
//!
//! Windows starts the program as `Aether.exe "C:\…\config.npvt"`. Nothing read
//! that argument: the first instance ignored `std::env::args()`, and the
//! single-instance hook (a second launch while Aether is already open) only
//! focused the window and threw `argv` away. So "Open with → Aether" just opened
//! the app and imported nothing. The installer also never registered `.npvt` /
//! `.npvs`, so a double-click did not reach Aether at all.
//!
//! # The fix
//!
//! * Every launch (first instance: `main`; later ones: the single-instance
//!   callback) passes its arguments to [`queue`], which keeps the existing files
//!   with a supported extension (the same list `import.rs` accepts).
//! * The UI drains the queue with [`take_open_files`] once it is ready, and
//!   again every time [`EVENT`] fires. A path is therefore never lost, even when
//!   the file arrives before the web view has finished loading.
//! * The import itself is the normal `cc_import_path` (password prompt, locks,
//!   size limit and all) — exactly what drag & drop uses.
//! * `installer/aether.iss` registers `.npvt` and `.npvs` (default handler and
//!   "Open with" entry) and removes the registration on uninstall.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Fired (no payload) when a later launch queued files; the UI then calls
/// [`take_open_files`].
pub const EVENT: &str = "aether://open-files";

/// Upper bound per launch: Explorer passes one path per selected file.
const MAX_FILES: usize = 64;

static PENDING: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// The config files among a launch's arguments (program path already removed).
///
/// Switches (`--minimized`, `-foo`) and anything that is not an existing file
/// with a supported extension are ignored. Relative paths are resolved against
/// `cwd` (the launching process's directory, which the single-instance plugin
/// reports). Order is kept; duplicates (case-insensitive, like NTFS) are dropped.
pub fn config_paths<I>(args: I, cwd: Option<&Path>) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut picked: Vec<String> = Vec::new();
    for raw in args {
        let arg = raw.trim().trim_matches('"').to_string();
        if arg.is_empty() || arg.starts_with('-') {
            continue;
        }
        let mut path = PathBuf::from(&arg);
        if path.is_relative() {
            if let Some(dir) = cwd {
                path = dir.join(path);
            }
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !crate::custom::import::FILE_EXTENSIONS.contains(&ext.as_str()) || !path.is_file() {
            continue;
        }
        picked.push(path.to_string_lossy().into_owned());
        if picked.len() >= MAX_FILES {
            break;
        }
    }
    crate::filedrop::normalize_paths(picked)
}

/// Adds paths to the queue; `true` when anything new was queued.
pub fn queue(paths: Vec<String>) -> bool {
    if paths.is_empty() {
        return false;
    }
    let mut pending = PENDING.lock().unwrap_or_else(|p| p.into_inner());
    let mut added = false;
    for p in paths {
        if !pending.iter().any(|q| q.eq_ignore_ascii_case(&p)) {
            pending.push(p);
            added = true;
        }
    }
    added
}

/// Hands the queued paths to the UI exactly once.
#[tauri::command]
pub fn take_open_files() -> Vec<String> {
    let mut pending = PENDING.lock().unwrap_or_else(|p| p.into_inner());
    std::mem::take(&mut *pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_existing_config_files_are_taken() {
        let dir = std::env::temp_dir().join(format!("aether-openfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let npvt = dir.join("a.npvt");
        let npvs = dir.join("B.NPVS");
        let exe = dir.join("x.exe");
        for f in [&npvt, &npvs, &exe] {
            std::fs::write(f, b"x").unwrap();
        }
        let args = vec![
            "--minimized".to_string(),
            npvt.to_string_lossy().into_owned(),
            format!("\"{}\"", npvs.to_string_lossy()),
            exe.to_string_lossy().into_owned(),
            dir.join("missing.npvt").to_string_lossy().into_owned(),
            npvt.to_string_lossy().into_owned(),
        ];
        let got = config_paths(args, None);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got[0].ends_with("a.npvt"));
        assert!(got[1].ends_with("B.NPVS"));
        // Relative to the launching directory.
        let rel = config_paths(vec!["a.npvt".to_string()], Some(dir.as_path()));
        assert_eq!(rel.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_queue_is_drained_once_and_deduplicated() {
        let _ = take_open_files();
        assert!(queue(vec!["C:\\x\\a.npvt".into()]));
        assert!(!queue(vec!["c:\\X\\A.npvt".into()]));
        assert!(!queue(Vec::new()));
        assert_eq!(take_open_files(), vec!["C:\\x\\a.npvt".to_string()]);
        assert!(take_open_files().is_empty());
    }
}
