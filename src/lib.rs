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
    #[error("MCAP file contained no end-of-data record")]
    NoEndOfData,
    #[error("Record parse failed")]
    Parse(#[from] binrw::Error),
    #[error("MCAP file ended in the middle of a record")]
    UnexpectedEof,
}

pub type McapResult<T> = Result<T, McapError>;

pub const MAGIC: &[u8] = &[0x89, b'M', b'C', b'A', b'P', 0x30, b'\r', b'\n'];

#[derive(Debug)]
pub enum RecordBody<'a> {
    Header(records::Header),
    Footer(records::Footer),
    Schema {
        header: records::SchemaHeader,
        data: Cow<'a, [u8]>,
    },
    Channel(records::Channel),
    Message {
        header: records::MessageHeader,
        data: Cow<'a, [u8]>,
    },
    Chunk {
        header: records::ChunkHeader,
        data: &'a [u8],
    },
    MessageIndex(records::MessageIndex),
    ChunkIndex(records::ChunkIndex),
    Attachment {
        header: records::AttachmentHeader,
        data: &'a [u8],
        crc: u32,
    },
    AttachmentIndex(records::AttachmentIndex),
    Statistics(records::Statistics),
    Metadata(records::Metadata),
    MetadataIndex(records::MetadataIndex),
    SummaryOffset(records::SummaryOffset),
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
        for record in self.flatten() {
            if let Record {
                contents: RecordBody::EndOfData(eod),
                ..
            } = record
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
        let contents = match read_record(kind, body) {
            Ok(k) => k,
            Err(e) => {
                self.malformed = true;
                return Some(Err(McapError::Parse(e)));
            }
        };

        self.buf = &self.buf[len as usize..];
        Some(Ok(Record {
            kind,
            len,
            contents,
        }))
    }
}

fn read_record(kind: u8, body: &[u8]) -> binrw::BinResult<RecordBody<'_>> {
    macro_rules! record {
        ($b:ident) => {
            let cur = Cursor::new($b);
            let res = cur.read_le()?;
            assert_eq!(b.len(), cur.position());
            res
        };
    }

    Ok(match kind {
        0x01 => RecordBody::Header(record!(body)),
        0x02 => RecordBody::Footer(record!(body)),
        0x03 => {
            let mut c = Cursor::new(body);
            let header: records::SchemaHeader = c.read_le()?;
            let data = Cow::Borrowed(&body[c.position() as usize..]);
            if header.data_len != data.len() as u32 {
                warn!(
                    "Schema {}'s data length doesn't match the total schema length",
                    header.name
                );
            }
            RecordBody::Schema { header, data }
        }
        0x04 => RecordBody::Channel(record!(body)),
        0x05 => {
            let mut c = Cursor::new(body);
            let header = c.read_le()?;
            let data = Cow::Borrowed(&body[c.position() as usize..]);
            RecordBody::Message { header, data }
        }
        0x06 => {
            let mut c = Cursor::new(body);
            let header = c.read_le()?;
            let data = &body[c.position() as usize..];
            RecordBody::Chunk { header, data }
        }
        0x07 => RecordBody::MessageIndex(record!(body)),
        0x08 => RecordBody::ChunkIndex(record!(body)),
        0x09 => {
            let mut c = Cursor::new(body);
            let header: records::AttachmentHeader = c.read_le()?;
            let data = &body[c.position() as usize..body.len() - 4];
            if header.data_len != data.len() as u64 {
                warn!(
                    "Schema {}'s data length doesn't match the total schema length",
                    header.name
                );
            }
            let crc = Cursor::new(&body[body.len() - 4..]).read_le()?;
            RecordBody::Attachment { header, data, crc }
        }
        0x0a => RecordBody::AttachmentIndex(record!(body)),
        0x0b => RecordBody::Statistics(record!(body)),
        0x0c => RecordBody::Metadata(record!(body)),
        0x0d => RecordBody::MetadataIndex(record!(body)),
        0x0e => RecordBody::SummaryOffset(record!(body)),
        0x0f => RecordBody::EndOfData(record!(body)),
        _ => RecordBody::Unknown(Cow::Borrowed(body)),
    })
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
