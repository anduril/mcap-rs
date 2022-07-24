mod records;

use binrw::prelude::*;
use log::*;
use thiserror::Error;

use std::{borrow::Cow, io::Cursor};

#[derive(Debug, Error)]
pub enum McapError {
    #[error("Bad magic number")]
    BadMagic,
    #[error("The CRC for the data section failed")]
    BadDataCrc,
    #[error("MCAP file ended in the middle of a record")]
    UnexpectedEof,
    #[error("MCAP file contained no end-of-data record")]
    NoEndOfData,
    #[error("Record parse failed")]
    Parse(#[from] binrw::Error),
}

pub type McapResult<T> = Result<T, McapError>;

pub const MAGIC: &[u8] = &[0x89, b'M', b'C', b'A', b'P', 0x30, b'\r', b'\n'];

#[derive(Debug)]
pub enum RecordBody<'a> {
    Header(records::Header),
    Footer(records::Footer),
    Schema(records::Schema),
    Channel(records::Channel),
    Message {
        header: records::MessageHeader,
        data: Cow<'a, [u8]>,
    },
    Chunk {
        header: records::ChunkHeader,
        data: &'a [u8],
    },
    EndOfData(records::EndOfData),
    Unknown(Cow<'a, [u8]>),
}

#[derive(Debug)]
pub struct Record<'a> {
    pub kind: u8,
    pub len: u64,
    pub contents: RecordBody<'a>,
}

pub struct LinearReader<'a> {
    buf: &'a [u8],
    malformed: bool,
}

impl<'a> LinearReader<'a> {
    pub fn new(buf: &'a [u8]) -> McapResult<Self> {
        if !buf.starts_with(MAGIC) || !buf.ends_with(MAGIC) {
            return Err(McapError::BadMagic);
        }
        let buf = &buf[MAGIC.len()..buf.len() - MAGIC.len()];

        {
            let checker = LinearReader {
                buf,
                malformed: false,
            };
            checker.check_data_crc()?;
        }

        Ok(Self {
            buf,
            malformed: false,
        })
    }

    fn check_data_crc(self) -> McapResult<()> {
        for record in self {
            if let Ok(Record {
                contents: RecordBody::EndOfData(eod),
                ..
            }) = record
            {
                if eod.data_section_crc == 0 {
                    debug!("File had no data section CRC");
                    return Ok(());
                } else {
                    todo!("Get a [start, EOD] slice and CRC it");
                }
            }
        }

        Err(McapError::NoEndOfData)
    }
}

impl<'a> Iterator for LinearReader<'a> {
    type Item = McapResult<Record<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }

        // After an unrecoverable error (due to something wonky in the file),
        // don't keep trying to walk it.
        if self.malformed {
            return None;
        }

        if self.buf.len() < 5 {
            warn!("Malformed MCAP - not enough space for record + length!");
            self.malformed = true;
            return Some(Err(McapError::UnexpectedEof));
        }

        let kind = read_u8(&mut self.buf);
        let len = read_u64(&mut self.buf);

        if self.buf.len() < len as usize {
            warn!(
                "Malformed MCAP - record with length {len}, but only {} bytes remain",
                self.buf.len()
            );
            self.malformed = true;
            return Some(Err(McapError::UnexpectedEof));
        }

        let body = &self.buf[..len as usize];

        // Boilerplate for bouncing parse errors out of the match below.
        macro_rules! check_parse {
            ($r:expr) => {
                match $r {
                    Ok(k) => k,
                    Err(e) => {
                        self.malformed = true;
                        return Some(Err(McapError::Parse(e)));
                    }
                }
            };
        }
        macro_rules! record {
            ($b:ident) => {
                check_parse!(Cursor::new($b).read_le())
            };
        }

        let contents = match kind {
            0x01 => RecordBody::Header(record!(body)),
            0x02 => RecordBody::Footer(record!(body)),
            0x03 => RecordBody::Schema(record!(body)),
            0x04 => RecordBody::Channel(record!(body)),
            0x05 => {
                let mut c = Cursor::new(body);
                let header = check_parse!(c.read_le());
                let data = Cow::Borrowed(&body[c.position() as usize..]);
                RecordBody::Message { header, data }
            }
            0x06 => {
                let mut c = Cursor::new(body);
                let header = check_parse!(c.read_le());
                let data = &body[c.position() as usize..];
                RecordBody::Chunk { header, data }
            }
            0x0f => RecordBody::EndOfData(record!(body)),
            _ => RecordBody::Unknown(Cow::Borrowed(body)),
        };

        self.buf = &self.buf[len as usize..];
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
