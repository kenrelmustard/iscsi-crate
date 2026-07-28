#![cfg(target_os = "linux")]

//! Linux physical disk backend for iSCSI target.
//!
//! This module provides a `ScsiBlockDevice` implementation that reads and writes
//! a Linux raw block device such as `/dev/sda`.

use crate::error::{IscsiError, ScsiResult};
use crate::scsi::ScsiBlockDevice;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// A Linux physical disk opened by path, usable as a SCSI block device.
pub struct LinuxPhysicalDisk {
    file: File,
    block_size: u32,
    read_only: bool,
}

impl LinuxPhysicalDisk {
    /// Open a block device path, e.g. `/dev/sda`.
    pub fn open<P: AsRef<Path>>(path: P, block_size: u32, read_only: bool) -> std::io::Result<Self> {
        let mut opts = OpenOptions::new();
        opts.read(true);

        if !read_only {
            opts.write(true);
        }

        let file = opts.open(path)?;
        Ok(Self {
            file,
            block_size,
            read_only,
        })
    }

    /// Open a block device path in read-only mode.
    pub fn open_read_only<P: AsRef<Path>>(path: P, block_size: u32) -> std::io::Result<Self> {
        Self::open(path, block_size, true)
    }

    fn seek_to_block(&mut self, lba: u64) -> std::io::Result<()> {
        let offset = lba.checked_mul(self.block_size as u64)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "LBA overflow"))?;
        self.file.seek(SeekFrom::Start(offset))?;
        Ok(())
    }
}

impl ScsiBlockDevice for LinuxPhysicalDisk {
    fn read(&self, lba: u64, blocks: u32, block_size: u32) -> ScsiResult<Vec<u8>> {
        if block_size != self.block_size {
            return Err(IscsiError::Scsi(format!(
                "block size mismatch: expected {}, got {}",
                self.block_size, block_size
            )));
        }

        let mut file = self.file.try_clone().map_err(IscsiError::Io)?;
        let offset = lba.checked_mul(block_size as u64)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "LBA overflow"))?;
        file.seek(SeekFrom::Start(offset)).map_err(IscsiError::Io)?;

        let mut buffer = vec![0u8; blocks as usize * block_size as usize];
        file.read_exact(&mut buffer).map_err(IscsiError::Io)?;
        Ok(buffer)
    }

    fn write(&mut self, lba: u64, data: &[u8], block_size: u32) -> ScsiResult<()> {
        if self.read_only {
            return Err(IscsiError::Scsi("device opened read-only".to_string()));
        }

        if block_size != self.block_size {
            return Err(IscsiError::Scsi(format!(
                "block size mismatch: expected {}, got {}",
                self.block_size, block_size
            )));
        }

        if data.len() % block_size as usize != 0 {
            return Err(IscsiError::Scsi("data length must be a multiple of block size".to_string()));
        }

        self.seek_to_block(lba).map_err(IscsiError::Io)?;
        self.file.write_all(data).map_err(IscsiError::Io)
    }

    fn capacity(&self) -> u64 {
        match self.file.metadata() {
            Ok(metadata) => metadata.len() / self.block_size as u64,
            Err(_) => 0,
        }
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn flush(&mut self) -> ScsiResult<()> {
        if self.read_only {
            return Ok(());
        }
        self.file.sync_all().map_err(IscsiError::Io)
    }

    fn vendor_id(&self) -> &str {
        "LINUX   "
    }

    fn product_id(&self) -> &str {
        "PhysicalDisk     "
    }

    fn product_rev(&self) -> &str {
        "1.0 "
    }
}
