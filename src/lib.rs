pub mod read;
pub mod records;
pub mod write;

mod io_utils;

use std::{borrow::Cow, collections::BTreeMap, fmt, sync::Arc};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum McapError {
    #[error("Bad magic number")]
    BadMagic,
    #[error("Footer record couldn't be found at the end of the file, before the magic bytes")]
    BadFooter,
    #[error("Attachment CRC failed (expeted {saved:08X}, got {calculated:08X}")]
    BadAttachmentCrc { saved: u32, calculated: u32 },
    #[error("Chunk CRC failed (expected {saved:08X}, got {calculated:08X}")]
    BadChunkCrc { saved: u32, calculated: u32 },
    #[error("Data section CRC failed (expected {saved:08X}, got {calculated:08X})")]
    BadDataCrc { saved: u32, calculated: u32 },
    #[error("Summary section CRC failed (expected {saved:08X}, got {calculated:08X})")]
    BadSummaryCrc { saved: u32, calculated: u32 },
    #[error("Index offset and length didn't point to the expected record type")]
    BadIndex,
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
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Schema<'a> {
    pub name: String,
    pub encoding: String,
    pub data: Cow<'a, [u8]>,
}

impl fmt::Debug for Schema<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Schema")
            .field("name", &self.name)
            .field("encoding", &self.encoding)
            .finish_non_exhaustive()
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub channel: Arc<Channel<'a>>,
    pub sequence: u32,
    pub log_time: u64,
    pub publish_time: u64,
    pub data: Cow<'a, [u8]>,
}

/// An attachment and its metadata in an MCAP file
#[derive(Debug, PartialEq, Eq)]
pub struct Attachment<'a> {
    pub log_time: u64,
    pub create_time: u64,
    pub name: String,
    pub content_type: String,
    pub data: Cow<'a, [u8]>,
}

pub use read::{MessageStream, Summary};
pub use write::Writer;
