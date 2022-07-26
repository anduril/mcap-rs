pub mod read;
pub mod records;
pub mod write;

mod io_utils;

use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum McapError {
    #[error("Bad magic number")]
    BadMagic,
    #[error("Chunk CRC failed")]
    BadChunkCrc,
    #[error("The CRC for the data section failed")]
    BadDataCrc,
    #[error("Channel `{0}` has mulitple records that don't match.")]
    ConflictingChannels(String),
    #[error("Schema `{0}` has mulitple records that don't match.")]
    ConflictingSchemas(String),
    #[error("Record parse failed")]
    Parse(#[from] binrw::Error),
    #[error("I/O error from writing, or reading a compression stream")]
    Io(#[from] std::io::Error),
    #[error("Schema has an ID of 0")]
    InvalidSchemaId,
    #[error("MCAP file ended in the middle of a record")]
    UnexpectedEof,
    #[error("Chunk ended in the middle of a record")]
    UnexpectedEoc,
    #[error("Message {0} referenced unknown channel {1}")]
    UnknownChannel(u32, u16),
    #[error("Channel `{0}` referenced unknown schema {1}")]
    UnknownSchema(String, u16),
    #[error("Found record with opcode {0:02X} in a chunk")]
    UnexpectedChunkRecord(u8),
    #[error("Unsupported compression format `{0}`")]
    UnsupportedCompression(String),
}

pub type McapResult<T> = Result<T, McapError>;

/// Magic bytes for the MCAP format
pub const MAGIC: &[u8] = &[0x89, b'M', b'C', b'A', b'P', 0x30, b'\r', b'\n'];

/// Describes a schema used by one or more [Channel]s in an MCAP file
///
/// The CoW can either borrow directly from the mapped file,
/// or hold its own buffer if it was decompressed from a chunk.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Schema<'a> {
    pub name: String,
    pub encoding: String,
    pub data: Cow<'a, [u8]>,
}

/// Describes a channel which [Message]s are published to in an MCAP file
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Channel<'a> {
    pub topic: String,
    pub schema: Option<Arc<Schema<'a>>>,

    pub message_encoding: String,
    pub metadata: BTreeMap<String, String>,
}

/// An event in an MCAP file, published to a [Channel]
///
/// The CoW can either borrow directly from the mapped file,
/// or hold its own buffer if it was decompressed from a chunk.
#[derive(Debug)]
pub struct Message<'a> {
    pub channel: Arc<Channel<'a>>,
    pub sequence: u32,
    pub log_time: u64,
    pub publish_time: u64,
    pub data: Cow<'a, [u8]>,
}

pub use read::MessageStream;
pub use write::McapWriter;
