mod records;

use log::*;
use thiserror::Error;

use std::borrow::Cow;

#[derive(Debug, Error)]
pub enum McapError {
    #[error("Bad magic number")]
    BadMagic,
    #[error("The CRC for the data section failed")]
    BadDataCrc,
    #[error("MCAP file ended in the middle of a record")]
    UnexpectedEof,
}

pub type McapResult<T> = Result<T, McapError>;

pub const MAGIC: &[u8] = &[0x89, b'M', b'C', b'A', b'P', 0x30, b'\r', b'\n'];

#[derive(Debug)]
pub struct Record<'a> {
    pub kind: u8,
    pub len: u64,
    pub contents: Cow<'a, [u8]>,
}

pub struct LinearReader<'a> {
    buf: &'a [u8],
}

impl<'a> LinearReader<'a> {
    pub fn new(buf: &'a [u8]) -> McapResult<Self> {
        if !buf.starts_with(MAGIC) || !buf.ends_with(MAGIC) {
            return Err(McapError::BadMagic);
        }
        let buf = &buf[MAGIC.len()..buf.len() - MAGIC.len()];

        {
            let checker = LinearReader { buf };
            checker.check_data_crc()?;
        }

        Ok(Self { buf })
    }

    fn check_data_crc(self) -> McapResult<()> {
        Ok(())
    }
}

impl<'a> Iterator for LinearReader<'a> {
    type Item = McapResult<Record<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }

        if self.buf.len() < 5 {
            warn!("Corrupt MCAP - not enough space for record + length!");
            return Some(Err(McapError::UnexpectedEof));
        }

        let kind = read_u8(&mut self.buf);
        let len = read_u64(&mut self.buf);

        if self.buf.len() < len as usize {
            warn!(
                "Corrupt MCAP - record with length {len}, but only {} bytes remain",
                self.buf.len()
            );
            return Some(Err(McapError::UnexpectedEof));
        }

        self.buf = &self.buf[len as usize..];
        let contents = Cow::Borrowed(self.buf);
        Some(Ok(Record {
            kind,
            len,
            contents,
        }))
    }
}

// All of the following panic if they walk off the back of the data block;
// callers are assumed to have made sure they got enough bytes back with
// `validate_response()`

/// Builds a `read_<type>(buf, index)` function that reads a given type
/// off the buffer at the given index.
macro_rules! reader {
    ($type:ty) => {
        paste::paste! {
            #[inline]
            fn [<read_ $type>](block: &mut &[u8]) -> $type {
                const SIZE: usize = std::mem::size_of::<$type>();
                let res = $type::from_le_bytes(
                    block[0..SIZE].try_into().unwrap()
                );
                *block = &block[SIZE..];
                res
            }
        }
    };
}

reader!(u8);
reader!(u64);
