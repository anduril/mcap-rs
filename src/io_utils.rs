use std::io::{self, prelude::*};

use crc32fast::Hasher;

/// Counts how many bytes have been read and calculates a running CRC32
pub struct CountingHashingReader<R> {
    inner: R,
    hasher: Hasher,
    count: u64,
}

impl<R: Read> CountingHashingReader<R> {
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

impl<R: Read> Read for CountingHashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let res = self.inner.read(buf)?;
        self.count += res as u64;
        self.hasher.update(&buf[..res]);
        Ok(res)
    }
}

pub struct CountingHashingWriter<W> {
    inner: W,
    hasher: Hasher,
    count: u64,
}

impl<W: Write> CountingHashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Hasher::new(),
            count: 0,
        }
    }

    pub fn position(&self) -> u64 {
        self.count
    }

    /// Consumes the reader and returns the inner writer and the checksum
    pub fn finalize(self) -> (W, u32) {
        (self.inner, self.hasher.finalize())
    }
}

impl<W: Write> Write for CountingHashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let res = self.inner.write(buf)?;
        self.count += res as u64;
        self.hasher.update(&buf[..res]);
        Ok(res)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
