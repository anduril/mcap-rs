use std::io::{self, prelude::*};

use crc32fast::Hasher;

/// Counts how many bytes have been read and calculates a running CRC32
pub struct CountingHasher<R> {
    inner: R,
    hasher: Hasher,
    count: u64,
}

impl<R: Read> CountingHasher<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Hasher::new(),
            count: 0,
        }
    }

    pub fn position(&self) -> u64 {
        self.count
    }

    /// Consumes the reader and returns the checksum
    pub fn finalize(self) -> u32 {
        self.hasher.finalize()
    }
}

impl<R: Read> Read for CountingHasher<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let res = self.inner.read(buf)?;
        self.count += res as u64;
        self.hasher.update(&buf[..res]);
        Ok(res)
    }
}
