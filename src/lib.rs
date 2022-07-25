mod read_utils;
pub mod records;

use std::{
    borrow::Cow,
    io::{prelude::*, Cursor},
};

use binrw::prelude::*;
use log::*;
use thiserror::Error;

use read_utils::CountingHasher;

#[derive(Debug, Error)]
pub enum McapError {
    #[error("Bad magic number")]
    BadMagic,
    #[error("A chunk CRC failed")]
    BadChunkCrc,
    #[error("The CRC for the data section failed")]
    BadDataCrc,
    #[error("MCAP file contained no end-of-data record")]
    NoEndOfData,
    #[error("Record parse failed")]
    Parse(#[from] binrw::Error),
    #[error("I/O error in compression stream")]
    Compression(#[from] std::io::Error),
    #[error("MCAP file ended in the middle of a record")]
    UnexpectedEof,
    #[error("Chunk ended in the middle of a record")]
    UnexpectedEoc,
    #[error("Found record with opcode {0:02X} in a chunk")]
    UnexpectedChunkRecord(u8),
    #[error("Unsupported compression format `{0}`")]
    UnsupportedCompression(String),
}

pub type McapResult<T> = Result<T, McapError>;

/// Magic bytes for the MCAP format
pub const MAGIC: &[u8] = &[0x89, b'M', b'C', b'A', b'P', 0x30, b'\r', b'\n'];

#[derive(Debug)]
pub enum Record<'a> {
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
    /// A record of unknown type
    Unknown {
        opcode: u8,
        data: Cow<'a, [u8]>,
    },
}

/// Scans a mapped MCAP file from start to end, returning each record.
///
/// You probably want a MessageReader instead - this yields the raw records
/// from the file without any postprocessing (CRC checks, decompressing chunks, etc.)
/// and is mostly meant as a building block for higher-level readers.
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
        Ok(Self::sans_magic(buf))
    }

    #[inline]
    fn sans_magic(buf: &'a [u8]) -> Self {
        Self {
            buf,
            malformed: false,
        }
    }

    fn check_data_crc(self) -> McapResult<()> {
        for record in self.flatten() {
            if let Record::EndOfData(eod) = record {
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

        let record = match read_record_from_slice(&mut self.buf) {
            Ok(k) => k,
            Err(e) => {
                self.malformed = true;
                return Some(Err(e));
            }
        };

        Some(Ok(record))
    }
}

fn read_record_from_slice<'a>(buf: &mut &'a [u8]) -> McapResult<Record<'a>> {
    if buf.len() < 5 {
        warn!("Malformed MCAP - not enough space for record + length!");
        return Err(McapError::UnexpectedEof);
    }

    let op = read_u8(buf);
    let len = read_u64(buf);

    if buf.len() < len as usize {
        warn!(
            "Malformed MCAP - record with length {len}, but only {} bytes remain",
            buf.len()
        );
        return Err(McapError::UnexpectedEof);
    }

    let body = &buf[..len as usize];
    let record = read_record(op, body)?;

    *buf = &buf[len as usize..];
    Ok(record)
}

fn read_record(op: u8, body: &[u8]) -> binrw::BinResult<Record<'_>> {
    macro_rules! record {
        ($b:ident) => {{
            let mut cur = Cursor::new($b);
            let res = cur.read_le()?;
            assert_eq!($b.len() as u64, cur.position());
            res
        }};
    }

    Ok(match op {
        0x01 => Record::Header(record!(body)),
        0x02 => Record::Footer(record!(body)),
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
            Record::Schema { header, data }
        }
        0x04 => Record::Channel(record!(body)),
        0x05 => {
            let mut c = Cursor::new(body);
            let header = c.read_le()?;
            let data = Cow::Borrowed(&body[c.position() as usize..]);
            Record::Message { header, data }
        }
        0x06 => {
            let mut c = Cursor::new(body);
            let header: records::ChunkHeader = c.read_le()?;
            let data = &body[c.position() as usize..];
            if header.compressed_size != data.len() as u64 {
                warn!("Chunk's compressed length doesn't match its header");
            }
            Record::Chunk { header, data }
        }
        0x07 => Record::MessageIndex(record!(body)),
        0x08 => Record::ChunkIndex(record!(body)),
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
            Record::Attachment { header, data, crc }
        }
        0x0a => Record::AttachmentIndex(record!(body)),
        0x0b => Record::Statistics(record!(body)),
        0x0c => Record::Metadata(record!(body)),
        0x0d => Record::MetadataIndex(record!(body)),
        0x0e => Record::SummaryOffset(record!(body)),
        0x0f => Record::EndOfData(record!(body)),
        opcode => Record::Unknown {
            opcode,
            data: Cow::Borrowed(body),
        },
    })
}

enum ChunkDecompressor<'a> {
    Null(LinearReader<'a>),
    Compressed {
        stream: Option<CountingHasher<Box<dyn Read + 'a>>>,
        malformed: bool,
    },
}

pub struct ChunkReader<'a> {
    header: records::ChunkHeader,
    decompressor: ChunkDecompressor<'a>,
}

impl<'a> ChunkReader<'a> {
    pub fn new(header: records::ChunkHeader, data: &'a [u8]) -> McapResult<Self> {
        let decompressor = match header.compression.as_str() {
            "zstd" => ChunkDecompressor::Compressed {
                stream: Some(CountingHasher::new(Box::new(
                    zstd::stream::read::Decoder::new(data)?,
                ))),
                malformed: false,
            },
            "lz4" => ChunkDecompressor::Compressed {
                stream: Some(CountingHasher::new(Box::new(lz4::Decoder::new(data)?))),
                malformed: false,
            },
            "" => {
                if header.uncompressed_size != header.compressed_size {
                    warn!(
                        "Chunk is uncompressed, but claims different compress/uncompressed lengths"
                    );
                }

                if header.uncompressed_crc != 0 && header.uncompressed_crc != crc32fast::hash(data)
                {
                    return Err(McapError::BadChunkCrc);
                }

                ChunkDecompressor::Null(LinearReader::sans_magic(data))
            }
            wat => return Err(McapError::UnsupportedCompression(wat.to_string())),
        };

        Ok(Self {
            header,
            decompressor,
        })
    }
}

impl<'a> Iterator for ChunkReader<'a> {
    type Item = McapResult<Record<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.decompressor {
            ChunkDecompressor::Null(r) => r.next(),
            ChunkDecompressor::Compressed { stream, malformed } => {
                // If we previously encountered an error in this stream, give up.
                if *malformed {
                    return None;
                }

                // If we consumed the stream last time to get the CRC, we're done.
                if stream.is_none() {
                    return None;
                }

                let s = stream.as_mut().unwrap();

                let record = match read_record_from_chunk_stream(s) {
                    Ok(k) => k,
                    Err(e) => {
                        *malformed = true;
                        return Some(Err(e));
                    }
                };

                // If we've read all there is to read...
                if s.position() == self.header.uncompressed_size {
                    // Get the CRC.
                    let calculated_crc = stream.take().unwrap().finalize();

                    // If the header stored a CRC
                    // and it doesn't match what we have, complain.
                    if self.header.uncompressed_crc != 0
                        && self.header.uncompressed_crc != calculated_crc
                    {
                        return Some(Err(McapError::BadChunkCrc));
                    }
                    // All good!
                    return None;
                }

                Some(Ok(record))
            }
        }
    }
}

fn read_record_from_chunk_stream<'a, R: Read>(r: &mut R) -> McapResult<Record<'a>> {
    use byteorder::{ReadBytesExt, LE};

    let op = r.read_u8()?;
    let len = r.read_u64::<LE>()?;

    Ok(match op {
        0x03 => {
            let mut record = Vec::new();
            r.take(len).read_to_end(&mut record)?;
            if len as usize != record.len() {
                return Err(McapError::UnexpectedEoc);
            }

            let mut c = Cursor::new(&record);
            let header: records::SchemaHeader = c.read_le()?;

            let header_end = c.position();

            // Should we rotate and shrink instead?
            let data = record.split_off(header_end as usize);

            if header.data_len as usize != data.len() {
                warn!(
                    "Schema {}'s data length doesn't match the total schema length",
                    header.name
                );
            }
            Record::Schema {
                header,
                data: Cow::Owned(data),
            }
        }
        0x04 => {
            let mut record = Vec::new();
            r.take(len).read_to_end(&mut record)?;
            if len as usize != record.len() {
                return Err(McapError::UnexpectedEoc);
            }

            let mut c = Cursor::new(&record);
            let channel: records::Channel = c.read_le()?;

            if c.position() != record.len() as u64 {
                warn!(
                    "Channel {}'s length doesn't match its record length",
                    channel.topic
                );
            }

            Record::Channel(channel)
        }
        0x05 => {
            // Optimization: messages are the mainstay of the file,
            // so allocate the header and the data separately.
            // Fortunately, message headers are fixed length.
            const HEADER_LEN: u64 = 22;

            let mut header_buf = Vec::new();
            r.take(HEADER_LEN).read_to_end(&mut header_buf)?;
            if header_buf.len() as u64 != HEADER_LEN {
                return Err(McapError::UnexpectedEoc);
            }
            let header: records::MessageHeader = Cursor::new(header_buf).read_le()?;

            let mut data = Vec::new();
            r.take(len - HEADER_LEN).read_to_end(&mut data)?;
            if data.len() as u64 != len - HEADER_LEN {
                return Err(McapError::UnexpectedEoc);
            }

            Record::Message {
                header,
                data: Cow::Owned(data),
            }
        }
        wut => return Err(McapError::UnexpectedChunkRecord(wut)),
    })
}

// All of the following panic if they walk off the back of the data block;
// callers are assumed to have made sure they got enoug bytes back with
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
