//! Write MCAP files

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    io::{self, prelude::*, Cursor, SeekFrom},
};

use binrw::prelude::*;

use crate::{
    io_utils::CountingHashingWriter,
    records::{self, Record},
    Channel, McapError, McapResult, Message, Schema, MAGIC,
};

pub use records::MessageHeader;

enum WriteMode<W: Write + Seek> {
    Raw(W),
    Chunk(ChunkWriter<W>),
}

fn op_and_len<W: Write>(w: &mut W, op: u8, len: usize) -> io::Result<()> {
    use byteorder::{WriteBytesExt, LE};
    w.write_u8(op)?;
    w.write_u64::<LE>(len as u64)?;
    Ok(())
}

fn write_record<W: Write>(w: &mut W, r: &Record) -> io::Result<()> {
    // Annoying: our stream isn't Seek, so we need an intermediate buffer.
    macro_rules! record {
        ($op:literal, $b:ident) => {{
            let mut rec_buf = Vec::new();
            Cursor::new(&mut rec_buf).write_le($b).unwrap();

            op_and_len(w, $op, rec_buf.len())?;
            w.write_all(&rec_buf)?;
        }};
    }

    macro_rules! header_and_data {
        ($op:literal, $header:ident, $data:ident) => {{
            let mut header_buf = Vec::new();
            Cursor::new(&mut header_buf).write_le($header).unwrap();

            op_and_len(w, $op, header_buf.len() + $data.len())?;
            w.write_all(&header_buf)?;
            w.write_all($data)?;
        }};
    }

    match r {
        Record::Header(h) => record!(0x01, h),
        Record::Footer(_) => {
            unreachable!("Footer handles its own serialization because its CRC is self-referencing")
        }
        Record::Schema { header, data } => header_and_data!(0x03, header, data),
        Record::Channel(c) => record!(0x04, c),
        Record::Message { header, data } => header_and_data!(0x05, header, data),
        Record::Chunk { .. } => {
            unreachable!("Chunks handle their own serialization due to seeking shenanigans")
        }
        Record::MessageIndex(_) => {
            unreachable!("MessageIndexes handle their own serialization to recycle the buffer between indexes")
        }
        Record::ChunkIndex(c) => record!(0x08, c),
        Record::Statistics(s) => record!(0x0B, s),
        Record::EndOfData(eod) => record!(0x0F, eod),
        _ => todo!(),
    };
    Ok(())
}

/// Writes an MCAP file to the given [Write]
///
/// Users should call [`finish()`](Self::finish) to flush the stream
/// and check for errors when done; otherwise the result will be unwrapped on drop.
pub struct McapWriter<'a, W: Write + Seek> {
    writer: Option<WriteMode<W>>,
    schemas: HashMap<Schema<'a>, u16>,
    channels: HashMap<Channel<'a>, u16>,
    stats: records::Statistics,
    chunk_indexes: Vec<records::ChunkIndex>,
}

impl<'a, W: Write + Seek> McapWriter<'a, W> {
    pub fn new(mut writer: W) -> McapResult<Self> {
        writer.write_all(MAGIC)?;

        write_record(
            &mut writer,
            &Record::Header(records::Header {
                profile: String::new(),
                library: String::from("mcap-rs 0.1"),
            }),
        )?;

        Ok(Self {
            writer: Some(WriteMode::Raw(writer)),
            schemas: HashMap::new(),
            channels: HashMap::new(),
            stats: records::Statistics::default(),
            chunk_indexes: Vec::new(),
        })
    }

    /// Adds a channel (and its provided schema, if any), returning its ID
    ///
    /// Useful with subequent calls to [`write_to_known_channel()`](Self::write_to_known_channel)
    pub fn add_channel(&mut self, chan: &Channel<'a>) -> McapResult<u16> {
        let schema_id = match &chan.schema {
            Some(s) => self.add_schema(&*s)?,
            None => 0,
        };

        if let Some(id) = self.channels.get(chan) {
            return Ok(*id);
        }

        let next_channel_id = self.channels.len() as u16;

        self.stats.channel_count += 1;
        assert!(self
            .channels
            .insert(chan.clone(), next_channel_id)
            .is_none());
        self.chunkin_time()?
            .write_channel(next_channel_id, schema_id, chan)?;
        Ok(next_channel_id)
    }

    /// Write the given message (and its provided channel, if needed).
    pub fn write(&mut self, message: &Message<'a>) -> McapResult<()> {
        let channel_id = self.add_channel(&message.channel)?;
        let header = MessageHeader {
            channel_id,
            sequence: message.sequence,
            log_time: message.log_time,
            publish_time: message.publish_time,
        };
        let data: &[u8] = &message.data;
        self.write_to_known_channel(&header, data)
    }

    /// Write a message to an added channel, given its ID.
    ///
    /// This skips hash lookups of the channel and schema if you already added them.
    pub fn write_to_known_channel(
        &mut self,
        header: &MessageHeader,
        data: &[u8],
    ) -> McapResult<()> {
        // The number of channels should be relatively small,
        // do a quick linear search to make sure we're not being given a bogus ID
        if !self.channels.values().any(|id| *id == header.channel_id) {
            return Err(McapError::UnknownChannel(
                header.sequence,
                header.channel_id,
            ));
        }

        self.stats.message_count += 1;
        self.stats.message_start_time = match self.stats.message_start_time {
            0 => header.log_time,
            nz => nz.min(header.log_time),
        };
        self.stats.message_end_time = match self.stats.message_end_time {
            0 => header.log_time,
            nz => nz.max(header.log_time),
        };
        *self
            .stats
            .channel_message_counts
            .entry(header.channel_id)
            .or_insert(0) += 1;

        self.chunkin_time()?.write_message(header, data)?;
        Ok(())
    }

    fn add_schema(&mut self, schema: &Schema<'a>) -> McapResult<u16> {
        if let Some(id) = self.schemas.get(schema) {
            return Ok(*id);
        }

        // Schema IDs cannot be zero, that's the sentinel value in a channel
        // for "no schema"
        let next_schema_id = self.schemas.len() as u16 + 1;

        self.stats.schema_count += 1;
        assert!(self
            .schemas
            .insert(schema.clone(), next_schema_id)
            .is_none());
        self.chunkin_time()?.write_schema(next_schema_id, schema)?;
        Ok(next_schema_id)
    }

    /// Starts a new chunk if we haven't done so already.
    fn chunkin_time(&mut self) -> McapResult<&mut ChunkWriter<W>> {
        // Some Rust tricky: we can't move the writer out of self.writer,
        // leave that empty for a bit, and then replace it with a ChunkWriter.
        // (That would leave it in an unspecified state if we bailed here!)
        // Instead briefly swap it out for a null writer while we set up the chunker
        let prev_writer = self.writer.take().unwrap();

        self.writer = Some(match prev_writer {
            WriteMode::Raw(w) => {
                // It's chunkin time.
                self.stats.chunk_count += 1;
                WriteMode::Chunk(ChunkWriter::new(w)?)
            }
            chunk => chunk,
        });

        match &mut self.writer {
            Some(WriteMode::Chunk(c)) => Ok(c),
            _ => unreachable!(),
        }
    }

    /// Finish the current chunk, if we have one.
    fn finish_chunk(&mut self) -> McapResult<&mut W> {
        // See above
        let prev_writer = self.writer.take().unwrap();

        self.writer = Some(match prev_writer {
            WriteMode::Chunk(c) => {
                let (w, index) = c.finish()?;
                self.chunk_indexes.push(index);
                WriteMode::Raw(w)
            }
            raw => raw,
        });

        match &mut self.writer {
            Some(WriteMode::Raw(w)) => Ok(w),
            _ => unreachable!(),
        }
    }

    /// Finishes any current chunks and writes out the rest of the file.
    ///
    /// Subsequent calls to other methods will panic.
    pub fn finish(&mut self) -> McapResult<()> {
        if self.writer.is_none() {
            // We already called finish().
            // Maybe we're dropping after the user called it?
            return Ok(());
        }

        // Finish any chunk we were working on and update stats, indexes, etc.
        self.finish_chunk()?;

        // Grab all the data we need for the summary now because we're about to
        // take a mutable borrow out on self.writer.
        // (We could get around all this noise by having finish() take self(),
        // but then it wouldn't be droppable _and_ finish...able.
        let mut stats = records::Statistics::default();
        std::mem::swap(&mut stats, &mut self.stats);

        let mut chunk_indexes = Vec::new();
        std::mem::swap(&mut chunk_indexes, &mut self.chunk_indexes);

        // Make some Schema and Channel lists for the summary section.
        // Be sure to grab schema IDs for the channels from the schema hash map before we drain it!
        struct ChannelSummary<'a> {
            channel: Channel<'a>,
            channel_id: u16,
            schema_id: u16,
        }

        let mut all_channels: Vec<ChannelSummary<'_>> = self
            .channels
            .drain()
            .map(|(channel, channel_id)| {
                let schema_id = match &channel.schema {
                    Some(s) => *self.schemas.get(s).unwrap(),
                    None => 0,
                };

                ChannelSummary {
                    channel,
                    channel_id,
                    schema_id,
                }
            })
            .collect();
        all_channels.sort_unstable_by_key(|cs| cs.channel_id);

        let mut all_schemas: Vec<(Schema<'_>, u16)> = self.schemas.drain().collect();
        all_schemas.sort_unstable_by_key(|(_, v)| *v);

        // We called finish_chunk() above, so we're back to raw writes for
        // the summary section.
        let writer = match &mut self.writer {
            Some(WriteMode::Raw(w)) => w,
            _ => unreachable!(),
        };

        // We're done with the data secton!
        write_record(writer, &Record::EndOfData(records::EndOfData::default()))?;

        let summary_start = writer.stream_position()?;

        // Let's get a CRC of the summary section.
        let mut summary_hasher = CountingHashingWriter::new(writer);

        // Write all schemas.
        for (schema, id) in all_schemas {
            let header = records::SchemaHeader {
                id,
                name: schema.name,
                encoding: schema.encoding,
                data_len: schema.data.len() as u32,
            };
            let data = schema.data;

            write_record(&mut summary_hasher, &Record::Schema { header, data })?;
        }
        // Write all channels.
        for cs in all_channels {
            let rec = records::Channel {
                id: cs.channel_id,
                schema_id: cs.schema_id,
                topic: cs.channel.topic,
                message_encoding: cs.channel.message_encoding,
                metadata: cs.channel.metadata,
            };
            write_record(&mut summary_hasher, &Record::Channel(rec))?;
        }

        // Write all chunk indexes.
        for index in chunk_indexes {
            write_record(&mut summary_hasher, &Record::ChunkIndex(index))?;
        }

        write_record(&mut summary_hasher, &Record::Statistics(stats))?;

        // In an incredibly bizarre move, the CRC of the footer _includes_
        // part of the footer. All of the wat.
        use byteorder::{WriteBytesExt, LE};
        op_and_len(&mut summary_hasher, 0x02, 20)?;
        summary_hasher.write_u64::<LE>(summary_start)?;
        summary_hasher.write_u64::<LE>(0)?; // Summary offsets not provided yet.

        let (writer, summary_crc) = summary_hasher.finalize();

        writer.write_u32::<LE>(summary_crc)?;

        writer.write_all(MAGIC)?;
        writer.flush()?;
        self.writer = None; // Make subsequent writes fail
        Ok(())
    }
}

impl<'a, W: Write + Seek> Drop for McapWriter<'a, W> {
    fn drop(&mut self) {
        self.finish().unwrap()
    }
}

struct ChunkWriter<W: Write + Seek> {
    header_start: u64,
    stream_start: u64,
    header: records::ChunkHeader,
    compressor: CountingHashingWriter<zstd::Encoder<'static, W>>,
    indexes: BTreeMap<u16, Vec<records::MessageIndexEntry>>,
}

impl<W: Write + Seek> ChunkWriter<W> {
    fn new(mut writer: W) -> McapResult<Self> {
        let header_start = writer.stream_position()?;

        op_and_len(&mut writer, 0x06, !0)?;
        let header = records::ChunkHeader {
            message_start_time: 0,
            message_end_time: 0,
            uncompressed_size: !0,
            uncompressed_crc: !0,
            compression: String::from("zstd"),
            compressed_size: !0,
        };

        writer.write_le(&header)?;
        let stream_start = writer.stream_position()?;

        let mut compressor = zstd::Encoder::new(writer, 0)?; // TODO: Compression options
        compressor.multithread(num_cpus::get_physical() as u32)?;
        let compressor = CountingHashingWriter::new(compressor);
        Ok(Self {
            compressor,
            header_start,
            stream_start,
            header,
            indexes: BTreeMap::new(),
        })
    }

    fn write_schema(&mut self, id: u16, schema: &Schema) -> McapResult<()> {
        let header = records::SchemaHeader {
            id,
            name: schema.name.clone(),
            encoding: schema.encoding.clone(),
            data_len: schema.data.len() as u32,
        };
        write_record(
            &mut self.compressor,
            &Record::Schema {
                header,
                data: Cow::Borrowed(&schema.data),
            },
        )?;
        Ok(())
    }

    fn write_channel(&mut self, id: u16, schema_id: u16, chan: &Channel) -> McapResult<()> {
        assert_eq!(schema_id == 0, chan.schema.is_none());

        let rec = records::Channel {
            id,
            schema_id,
            topic: chan.topic.clone(),
            message_encoding: chan.message_encoding.clone(),
            metadata: chan.metadata.clone(),
        };

        write_record(&mut self.compressor, &Record::Channel(rec))?;
        Ok(())
    }

    fn write_message(&mut self, header: &MessageHeader, data: &[u8]) -> McapResult<()> {
        // Update min/max time
        self.header.message_start_time = match self.header.message_start_time {
            0 => header.log_time,
            nz => nz.min(header.log_time),
        };
        self.header.message_end_time = match self.header.message_end_time {
            0 => header.log_time,
            nz => nz.max(header.log_time),
        };

        // Add an index for this message
        self.indexes
            .entry(header.channel_id)
            .or_default()
            .push(records::MessageIndexEntry {
                log_time: header.log_time,
                offset: self.compressor.position(),
            });

        write_record(
            &mut self.compressor,
            &Record::Message {
                header: *header,
                data: Cow::Borrowed(data),
            },
        )?;
        Ok(())
    }

    fn finish(mut self) -> McapResult<(W, records::ChunkIndex)> {
        // Get the number of uncompressed bytes written and the CRC.
        self.header.uncompressed_size = self.compressor.position();
        let (zstd_stream, crc) = self.compressor.finalize();
        self.header.uncompressed_crc = crc;

        // Finalize the ztsd stream - it maintains an internal buffer.
        let mut writer = zstd_stream.finish()?;
        let end_of_stream = writer.stream_position()?;
        self.header.compressed_size = end_of_stream - self.stream_start;
        let record_size = (end_of_stream - self.header_start) as usize - 9; // 1 byte op, 8 byte len

        // Back up, write our finished header, then continue at the end of the stream.
        writer.seek(SeekFrom::Start(self.header_start))?;
        op_and_len(&mut writer, 0x06, record_size)?;
        writer.write_le(&self.header)?;
        assert_eq!(self.stream_start, writer.stream_position()?);
        assert_eq!(writer.seek(SeekFrom::End(0))?, end_of_stream);

        // Write our message indexes
        let mut message_index_offsets: BTreeMap<u16, u64> = BTreeMap::new();

        let mut index_buf = Vec::new();
        for (channel_id, records) in self.indexes {
            assert!(message_index_offsets
                .insert(channel_id, writer.stream_position()?)
                .is_none());
            index_buf.clear();
            let index = records::MessageIndex {
                channel_id,
                records,
            };

            Cursor::new(&mut index_buf).write_le(&index)?;
            op_and_len(&mut writer, 0x07, index_buf.len())?;
            writer.write_all(&index_buf)?;
        }
        let end_of_indexes = writer.stream_position()?;

        let index = records::ChunkIndex {
            message_start_time: self.header.message_start_time,
            message_end_time: self.header.message_end_time,
            chunk_start_offset: self.header_start,
            chunk_length: end_of_stream - self.header_start,
            message_index_offsets,
            message_index_length: end_of_indexes - end_of_stream,
            compression: self.header.compression,
            compressed_size: self.header.compressed_size,
            uncompressed_size: self.header.uncompressed_size,
        };

        Ok((writer, index))
    }
}
