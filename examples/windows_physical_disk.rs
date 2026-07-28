//! Windows physical disk example for iSCSI target.
//!
//! This example shows how to expose a Windows physical disk device as an
//! iSCSI target using the `WindowsPhysicalDisk` backend.

#[cfg(target_os = "windows")]
use iscsi_target::{IscsiTarget, ScsiBlockDevice, WindowsPhysicalDisk};
#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("This example is only supported on Windows.");
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    if !is_elevated() {
        println!("Administrator privileges are required. Requesting elevation...");
        elevate_self()?;
        return Ok(());
    }

    let mut args = std::env::args().skip(1);
    let mut disk_path = "\\.\\PhysicalDrive0".to_string();

    if let Some(path) = args.next() {
        disk_path = path.to_string();
    }

    let block_size = 512;
    let storage = WindowsPhysicalDisk::open_read_only(&disk_path, block_size)?;

    let target = IscsiTarget::builder()
        .bind_addr("0.0.0.0:3260")
        .target_name("iqn.2026-07.com.example:windows-physical-disk")
        .target_alias("Windows Physical Disk")
        .build(storage)?;

    println!("Starting iSCSI target exposing physical disk: {}", disk_path);
    println!("Use the Windows iSCSI Initiator to connect to 127.0.0.1:3260");

    target.run()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn to_wide_null(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(target_os = "windows")]
fn elevate_self() -> std::io::Result<()> {
    let exe_path = std::env::current_exe()?;
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let args_string = args
        .iter()
        .map(|arg| {
            let s = arg.to_string_lossy();
            if s.contains(' ') {
                format!("\"{}\"", s)
            } else {
                s.into_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let operation = to_wide_null(OsStr::new("runas"));
    let file = to_wide_null(exe_path.as_os_str());
    let params = to_wide_null(OsStr::new(&args_string));

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            if args_string.is_empty() {
                std::ptr::null()
            } else {
                params.as_ptr()
            },
            std::ptr::null(),
            1,
        )
    };

    if result as isize <= 32 {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Elevation request failed: status {}", result as isize),
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
#[link(name = "shell32")]
extern "system" {
    fn ShellExecuteW(
        hwnd: *mut std::ffi::c_void,
        lpOperation: *const u16,
        lpFile: *const u16,
        lpParameters: *const u16,
        lpDirectory: *const u16,
        nShowCmd: i32,
    ) -> isize;

    fn IsUserAnAdmin() -> i32;
}
