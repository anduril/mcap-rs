//! Read MCAP files

use std::{
    borrow::Cow,
    collections::HashMap,
    io::{prelude::*, Cursor},
    sync::Arc,
};

use binrw::prelude::*;
use crc32fast::hash as crc32;
use log::*;

use crate::{
    io_utils::CountingHashingReader,
    records::{self, Record},
    Channel, McapError, McapResult, Message, Schema, MAGIC,
};

/// Scans a mapped MCAP file from start to end, returning each record.
///
/// You probably want a [MessageStream] instead - this yields the raw records
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

    fn sans_magic(buf: &'a [u8]) -> Self {
        Self {
            buf,
            malformed: false,
        }
    }

    /// Returns the number of unprocessed bytes
    /// (sans the file's starting and ending magic)
    ///
    /// Used to calculate offsets for the data section et al.
    fn bytes_remaining(&self) -> usize {
        self.buf.len()
    }
}

impl<'a> Iterator for LinearReader<'a> {
    type Item = McapResult<records::Record<'a>>;

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

/// Read a record and advance the slice
fn read_record_from_slice<'a>(buf: &mut &'a [u8]) -> McapResult<records::Record<'a>> {
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
    debug!("slice: opcode {op:02X}, length {len}");
    let record = read_record(op, body)?;
    trace!("       {:?}", record);

    *buf = &buf[len as usize..];
    Ok(record)
}

/// Given a record's opcode and its slice, read it into a [Record]
fn read_record(op: u8, body: &[u8]) -> binrw::BinResult<records::Record<'_>> {
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
    Compressed(Option<CountingHashingReader<Box<dyn Read + 'a>>>),
}

/// Streams records out of a [Chunk](Record::Chunk), decompressing as needed.
pub struct ChunkReader<'a> {
    header: records::ChunkHeader,
    decompressor: ChunkDecompressor<'a>,
}

impl<'a> ChunkReader<'a> {
    pub fn new(header: records::ChunkHeader, data: &'a [u8]) -> McapResult<Self> {
        let decompressor = match header.compression.as_str() {
            "zstd" => ChunkDecompressor::Compressed(Some(CountingHashingReader::new(Box::new(
                zstd::Decoder::new(data)?,
            )))),
            "lz4" => ChunkDecompressor::Compressed(Some(CountingHashingReader::new(Box::new(
                lz4::Decoder::new(data)?,
            )))),
            "" => {
                if header.uncompressed_size != header.compressed_size {
                    warn!(
                        "Chunk is uncompressed, but claims different compress/uncompressed lengths"
                    );
                }

                if header.uncompressed_crc != 0 && header.uncompressed_crc != crc32(data) {
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
    type Item = McapResult<records::Record<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.decompressor {
            ChunkDecompressor::Null(r) => r.next(),
            ChunkDecompressor::Compressed(stream) => {
                // If we consumed the stream last time to get the CRC,
                // or because of an error, we're done.
                if stream.is_none() {
                    return None;
                }

                let s = stream.as_mut().unwrap();

                let record = match read_record_from_chunk_stream(s) {
                    Ok(k) => k,
                    Err(e) => {
                        *stream = None; // Don't try to recover.
                        return Some(Err(e));
                    }
                };

                // If we've read all there is to read...
                if s.position() >= self.header.uncompressed_size {
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
                }

                Some(Ok(record))
            }
        }
    }
}

/// Like [read_record_from_slice], but for a decompression stream
fn read_record_from_chunk_stream<'a, R: Read>(r: &mut R) -> McapResult<records::Record<'a>> {
    // We can't use binrw because compressions streams aren't seekable.
    // byteorder time!
    use byteorder::{ReadBytesExt, LE};

    let op = r.read_u8()?;
    let len = r.read_u64::<LE>()?;

    debug!("chunk: opcode {op:02X}, length {len}");
    let record = match op {
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
            // so allocate the header and the data separately to avoid having
            // to split them up or move them around later.
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
    };
    trace!("       {:?}", record);
    Ok(record)
}

/// Flattens chunks into the top-level record stream
pub struct ChunkFlattener<'a> {
    top_level: LinearReader<'a>,
    dechunk: Option<ChunkReader<'a>>,
    malformed: bool,
}

impl<'a> ChunkFlattener<'a> {
    pub fn new(buf: &'a [u8]) -> McapResult<Self> {
        let top_level = LinearReader::new(buf)?;
        Ok(Self {
            top_level,
            dechunk: None,
            malformed: false,
        })
    }

    fn bytes_remaining(&self) -> usize {
        self.top_level.bytes_remaining()
    }
}

impl<'a> Iterator for ChunkFlattener<'a> {
    type Item = McapResult<records::Record<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.malformed {
            return None;
        }

        let n: Option<Self::Item> = loop {
            // If we're reading from a chunk, do that until it returns None.
            if let Some(d) = &mut self.dechunk {
                match d.next() {
                    Some(d) => break Some(d),
                    None => self.dechunk = None,
                }
            }
            // Fall through - if we didn't extract a record from a chunk
            // (or that chunk ended), move on to the next top-level record.
            match self.top_level.next() {
                // If it's a chunk, get a new chunk reader going...
                Some(Ok(Record::Chunk { header, data })) => {
                    self.dechunk = match ChunkReader::new(header, data) {
                        Ok(d) => Some(d),
                        Err(e) => break Some(Err(e)),
                    };
                    // ...then continue the loop to get the first item from the chunk.
                }
                // If it's not a chunk, just yield it.
                not_a_chunk => break not_a_chunk,
            }
        };

        // Give up on errors
        if matches!(n, Some(Err(_))) {
            self.malformed = true;
        }
        n
    }
}

/// Read all messages from the MCAP file in the order they were written,
/// and perform needed validation (CRC checks, etc.) as we go.
///
/// This stops at the end of the data section and does not read the summary.
pub struct MessageStream<'a> {
    full_file: &'a [u8],
    records: ChunkFlattener<'a>,
    done: bool,

    schemas: HashMap<u16, Arc<Schema<'a>>>,
    channels: HashMap<u16, Arc<Channel<'a>>>,
}

impl<'a> MessageStream<'a> {
    pub fn new(buf: &'a [u8]) -> McapResult<Self> {
        let full_file = buf;
        let records = ChunkFlattener::new(buf)?;

        Ok(Self {
            full_file,
            records,
            done: false,
            schemas: HashMap::new(),
            channels: HashMap::new(),
        })
    }
}

impl<'a> Iterator for MessageStream<'a> {
    type Item = McapResult<Message<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let n = loop {
            // Let's start with a working record.
            let record = match self.records.next() {
                Some(Ok(rec)) => rec,
                Some(Err(e)) => break Some(Err(e)),
                None => break None,
            };

            match record {
                // Insert schemas into self so we know when subsequent channels reference them.
                Record::Schema { header, data } => {
                    if header.id == 0 {
                        break Some(Err(McapError::InvalidSchemaId));
                    }

                    if let Some(preexisting) = self.schemas.get(&header.id) {
                        // Oh boy, we have this schema already.
                        // It had better be identital.
                        if header.name != preexisting.name
                            || header.encoding != preexisting.encoding
                            || data != preexisting.data
                        {
                            break Some(Err(McapError::ConflictingSchemas(header.name)));
                        }
                    } else {
                        let schema = Arc::new(Schema {
                            name: header.name,
                            encoding: header.encoding,
                            data,
                        });
                        assert!(self.schemas.insert(header.id, schema).is_none());
                    }
                }

                // Insert channels into self so we know when subsequent messages reference them.
                Record::Channel(chan) => {
                    if let Some(preexisting) = self.channels.get(&chan.id) {
                        // Oh boy, we have this channel already.
                        // It had better be identital.
                        if chan.topic != preexisting.topic
                            || chan.message_encoding != preexisting.message_encoding
                            || chan.metadata != preexisting.metadata
                            || self.schemas.get(&chan.schema_id) != preexisting.schema.as_ref()
                        {
                            break Some(Err(McapError::ConflictingChannels(chan.topic)));
                        }
                    } else {
                        // The schema ID can be 0 for "no schema",
                        // Or must reference some previously-read schema.
                        let schema = if chan.schema_id == 0 {
                            None
                        } else {
                            match self.schemas.get(&chan.schema_id) {
                                Some(s) => Some(s.clone()),
                                None => {
                                    break Some(Err(McapError::UnknownSchema(
                                        chan.topic,
                                        chan.schema_id,
                                    )))
                                }
                            }
                        };

                        let channel = Arc::new(Channel {
                            topic: chan.topic,
                            schema,
                            message_encoding: chan.message_encoding,
                            metadata: chan.metadata,
                        });
                        assert!(self.channels.insert(chan.id, channel).is_none());
                    }
                }

                Record::Message { header, data } => {
                    // Messages must have a previously-read channel.
                    let channel = match self.channels.get(&header.channel_id) {
                        Some(c) => c.clone(),
                        None => {
                            break Some(Err(McapError::UnknownChannel(
                                header.sequence,
                                header.channel_id,
                            )))
                        }
                    };

                    let m = Message {
                        channel,
                        sequence: header.sequence,
                        log_time: header.log_time,
                        publish_time: header.publish_time,
                        data,
                    };
                    break Some(Ok(m));
                }

                // If it's EOD, do unholy things to calculate the CRC.
                Record::EndOfData(end) => {
                    if end.data_section_crc != 0 {
                        // This is terrible. Less math with less magic numbers, please.
                        let data_section_len = (self.full_file.len() - MAGIC.len() * 2) // Actual working area
                            - self.records.bytes_remaining();

                        let data_section =
                            &self.full_file[MAGIC.len()..MAGIC.len() + data_section_len];
                        if end.data_section_crc != crc32(data_section) {
                            break Some(Err(McapError::BadDataCrc));
                        }
                    }
                    break None; // We're done at any rate.
                }
                _skip => {}
            };
        };

        if !matches!(n, Some(Ok(_))) {
            self.done = true;
        }
        n
    }
}

// All of the following panic if they walk off the back of the data block;
// callers are assumed to have made sure they got enoug bytes back with
// `validate_response()`

/// Builds a `read_<type>(&mut buf)` function that reads a given type
/// off the buffer and advances it the appropriate number of bytes.
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
