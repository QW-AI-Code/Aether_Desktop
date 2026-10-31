//! Native Windows "Save as" dialog for exported profiles.
//!
//! The webview's `<a download>` trick shows no dialog in WebView2 (the file is
//! saved silently or not at all), so the choice of folder and name is made
//! here with the shell's `IFileSaveDialog`. Returns `Ok(None)` on Cancel.
use std::path::PathBuf;

#[cfg(windows)]
pub fn pick_save_path(owner: isize, suggested: &str) -> Result<Option<PathBuf>, String> {
    use windows::core::{w, HSTRING};
    use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
    use windows::Win32::UI::Shell::{
        FileSaveDialog, IFileSaveDialog, FOS_FORCEFILESYSTEM, FOS_OVERWRITEPROMPT, FOS_PATHMUSTEXIST,
        SIGDN_FILESYSPATH,
    };

    fn run(owner: isize, suggested: &str) -> windows::core::Result<Option<PathBuf>> {
        unsafe {
            let dialog: IFileSaveDialog = CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER)?;
            let options = dialog.GetOptions()?;
            dialog.SetOptions(options | FOS_OVERWRITEPROMPT | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST)?;
            dialog.SetFileTypes(&[COMDLG_FILTERSPEC { pszName: w!("JSON"), pszSpec: w!("*.json") }])?;
            dialog.SetDefaultExtension(w!("json"))?;
            dialog.SetFileName(&HSTRING::from(suggested))?;
            if let Err(e) = dialog.Show(HWND(owner as *mut core::ffi::c_void)) {
                if e.code() == ERROR_CANCELLED.to_hresult() { return Ok(None); }
                return Err(e);
            }
            let item = dialog.GetResult()?;
            let raw = item.GetDisplayName(SIGDN_FILESYSPATH)?;
            let path = raw.to_string().map_err(|_| windows::core::Error::from(ERROR_CANCELLED))?;
            CoTaskMemFree(Some(raw.0 as *const core::ffi::c_void));
            Ok(Some(PathBuf::from(path)))
        }
    }

    // SAFETY: COM is initialised and released on this dedicated thread only.
    let init = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let result = run(owner, suggested).map_err(|e| e.message());
    if init.is_ok() { unsafe { CoUninitialize() }; }
    result
}

#[cfg(not(windows))]
pub fn pick_save_path(_owner: isize, _suggested: &str) -> Result<Option<PathBuf>, String> {
    Err("Save dialog is only available on Windows".into())
}
