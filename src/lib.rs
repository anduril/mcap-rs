mod records;

use streaming_iterator::StreamingIterator;
use log::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum McapError {
    #[error("Bad magic number")]
    BadMagic,
}

pub type McapResult<T> = Result<T, McapError>;

pub const MAGIC: &[u8] = &[0x89, b'M', b'C', b'A', b'P', 0x30, b'\r', b'\n'];

#[derive(Debug)]
pub struct Record {
    kind: u8,
    len: u64
}

pub struct LinearReader<'a> {
    buf: &'a [u8],
    current: Option<Record>,
}

impl<'a> LinearReader<'a> {
    pub fn new(buf: &'a [u8]) -> McapResult<Self> {
        if !buf.starts_with(MAGIC) || !buf.ends_with(MAGIC) {
            return Err(McapError::BadMagic);
        }
        let buf = &buf[MAGIC.len()..buf.len() - MAGIC.len()];
        Ok(Self { buf, current: None })
    }
}

impl StreamingIterator for LinearReader<'_> {
    type Item = Record;

    fn advance(&mut self) {
        if self.buf.is_empty() {
            self.current = None;
            return;
        }

        if self.buf.len() < 5 {
            warn!("Corrupt MCAP - not enough space for record + length!");
            self.current = None;
            return;
        }

        let kind = read_u8(&mut self.buf);
        let len = read_u64(&mut self.buf);

        if self.buf.len() < len as usize {
            warn!("Corrupt MCAP - record with length {len}, but only {} bytes remain", self.buf.len());
            self.current = None;
        } else {
            self.buf = &self.buf[len as usize..];
            self.current = Some(Record { kind, len });
        }
    }

    fn get(&self) -> Option<&Self::Item> {
        self.current.as_ref()
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
