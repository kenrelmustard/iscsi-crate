#![cfg(target_os = "windows")]

use iscsi_target::{IscsiClient, IscsiTarget, ScsiBlockDevice, ScsiResult};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct WindowsTestStorage {
    data: Vec<u8>,
}

impl ScsiBlockDevice for WindowsTestStorage {
    fn read(&self, lba: u64, blocks: u32, block_size: u32) -> ScsiResult<Vec<u8>> {
        let offset = (lba * block_size as u64) as usize;
        let len = (blocks * block_size as usize) as usize;

        if offset + len > self.data.len() {
            return Err(iscsi_target::IscsiError::Scsi(
                "Read beyond storage capacity".to_string(),
            ));
        }

        Ok(self.data[offset..offset + len].to_vec())
    }

    fn write(&mut self, lba: u64, data: &[u8], block_size: u32) -> ScsiResult<()> {
        let offset = (lba * block_size as u64) as usize;

        if offset + data.len() > self.data.len() {
            return Err(iscsi_target::IscsiError::Scsi(
                "Write beyond storage capacity".to_string(),
            ));
        }

        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn capacity(&self) -> u64 {
        (self.data.len() / 512) as u64
    }

    fn block_size(&self) -> u32 {
        512
    }

    fn flush(&mut self) -> ScsiResult<()> {
        Ok(())
    }
}

fn find_free_port() -> u16 {
    for _ in 0..10 {
        if let Ok(listener) = TcpListener::bind("127.0.0.1:0") {
            if let Ok(port) = listener.local_addr().map(|addr| addr.port()) {
                drop(listener);
                return port;
            }
        }
    }

    panic!("Unable to acquire a free TCP port for Windows test")
}

#[test]
fn windows_target_accepts_connection_and_allows_login() {
    let port = find_free_port();
    let bind_addr = format!("127.0.0.1:{}", port);
    let target_name = "iqn.2026-07.com.example:windows-test";
    let initiator_name = "iqn.2026-07.com.example:windows-initiator";

    let storage = WindowsTestStorage {
        data: vec![0u8; 16 * 1024 * 1024],
    };

    let target = IscsiTarget::builder()
        .bind_addr(&bind_addr)
        .target_name(target_name)
        .build(storage)
        .expect("Failed to build iSCSI target");

    let target = Arc::new(target);
    let target_handle = Arc::clone(&target);

    let server_thread = thread::spawn(move || {
        target_handle
            .run()
            .expect("iSCSI target server should run successfully");
    });

    std::thread::sleep(Duration::from_millis(250));

    let mut client = IscsiClient::connect(&bind_addr)
        .expect("Failed to connect to Windows iSCSI target");

    client
        .login(initiator_name, target_name)
        .expect("Failed to login to Windows iSCSI target");
    assert!(client.is_logged_in(), "Client should be logged in after successful login");

    client.logout().expect("Failed to logout from Windows iSCSI target");

    target.stop();
    server_thread
        .join()
        .expect("Windows iSCSI server thread should join cleanly");
}
