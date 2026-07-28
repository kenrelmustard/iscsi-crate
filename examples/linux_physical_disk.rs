//! Linux physical disk example for iSCSI target.
//!
//! This example shows how to expose a Linux block device as an iSCSI target
//! using the `LinuxPhysicalDisk` backend.

#[cfg(target_os = "linux")]
use iscsi_target::{IscsiTarget, ScsiBlockDevice, LinuxPhysicalDisk};

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example is only supported on Linux.");
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut args = std::env::args().skip(1);
    let mut device_path = "/dev/sda".to_string();
    let mut read_only = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--read-only" | "-r" => {
                read_only = true;
            }
            path => {
                device_path = path.to_string();
            }
        }
    }

    let block_size = 512;
    let storage = if read_only {
        LinuxPhysicalDisk::open_read_only(&device_path, block_size)?
    } else {
        LinuxPhysicalDisk::open(&device_path, block_size, false)?
    };

    let target = IscsiTarget::builder()
        .bind_addr("0.0.0.0:3260")
        .target_name("iqn.2026-07.com.example:linux-physical-disk")
        .target_alias("Linux Physical Disk")
        .build(storage)?;

    println!("Starting iSCSI target exposing device: {}", device_path);
    println!("Use an iSCSI initiator to connect to 127.0.0.1:3260");
    println!("Run as root or with sufficient privileges to open block devices.");

    target.run()?;
    Ok(())
}
