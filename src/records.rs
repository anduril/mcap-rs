//! Raw records parsed from an MCAP file
//!
//! See <https://github.com/foxglove/mcap/tree/main/docs/specification>

use binrw::io::{Read, Seek, Write};
use binrw::*;

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[binrw]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct McapString {
    #[br(temp)]
    #[bw(calc = inner.len() as u32)]
    pub len: u32,

    #[br(count = len, try_map = String::from_utf8)]
    #[bw(map = |s| s.as_bytes())]
    pub inner: String,
}

/// Avoids taking a copy to turn a String to an McapString for serialization
fn write_string<W: binrw::io::Write + binrw::io::Seek>(
    s: &String,
    w: &mut W,
    opts: &WriteOptions,
    args: (),
) -> BinResult<()> {
    (s.len() as u32).write_options(w, opts, args)?;
    (s.as_bytes()).write_options(w, opts, args)?;
    Ok(())
}

fn parse_vec<T: binrw::BinRead<Args = ()>, R: Read + Seek>(
    reader: &mut R,
    ro: &ReadOptions,
    args: (),
) -> BinResult<Vec<T>> {
    let mut parsed = Vec::new();

    // Length of the map in BYTES, not records.
    let byte_len: u32 = BinRead::read_options(reader, ro, args)?;
    let pos = reader.stream_position()?;

    while (reader.stream_position()? - pos) < byte_len as u64 {
        parsed.push(T::read_options(reader, ro, args)?);
    }

    Ok(parsed)
}

fn write_vec<W: binrw::io::Write + binrw::io::Seek, T: binrw::BinWrite<Args = ()>>(
    v: &Vec<T>,
    w: &mut W,
    opts: &WriteOptions,
    args: (),
) -> BinResult<()> {
    (v.len() as u32).write_options(w, opts, args)?;
    for e in v.iter() {
        e.write_options(w, opts, args)?;
    }
    Ok(())
}

#[derive(Debug, Clone, BinRead, BinWrite)]
pub struct Header {
    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub profile: String,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub library: String,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct Footer {
    pub summary_start: u64,
    pub summary_offset_start: u64,
    pub summary_crc: u32,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct SchemaHeader {
    pub id: u16,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub name: String,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub encoding: String,

    pub data_len: u32,
}

fn parse_string_map<R: Read + Seek>(
    reader: &mut R,
    ro: &ReadOptions,
    args: (),
) -> BinResult<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();

    // Length of the map in BYTES, not records.
    let byte_len: u32 = BinRead::read_options(reader, ro, args)?;
    let pos = reader.stream_position()?;

    while (reader.stream_position()? - pos) < byte_len as u64 {
        let k = McapString::read_options(reader, ro, args)?;
        let v = McapString::read_options(reader, ro, args)?;
        if let Some(_prev) = parsed.insert(k.inner, v.inner) {
            return Err(binrw::Error::Custom {
                pos,
                err: Box::new("Duplicate keys in map"),
            });
        }
    }

    Ok(parsed)
}

fn write_string_map<W: Write + Seek>(
    s: &BTreeMap<String, String>,
    w: &mut W,
    opts: &WriteOptions,
    args: (),
) -> BinResult<()> {
    // Ugh: figure out total number of bytes to write:
    let mut byte_len = 0;
    for (k, v) in s {
        byte_len += 8; // Four bytes each for lengths of key and value
        byte_len += k.len();
        byte_len += v.len();
    }

    (byte_len as u32).write_options(w, opts, args)?;
    let pos = w.stream_position()?;

    for (k, v) in s {
        write_string(k, w, opts, args)?;
        write_string(v, w, opts, args)?;
    }
    assert_eq!(w.stream_position()?, pos + byte_len as u64);
    Ok(())
}

fn write_int_map<K: BinWrite<Args = ()>, V: BinWrite<Args = ()>, W: Write + Seek>(
    s: &BTreeMap<K, V>,
    w: &mut W,
    opts: &WriteOptions,
    args: (),
) -> BinResult<()> {
    // Ugh: figure out total number of bytes to write:
    let mut byte_len = 0;
    for _ in s.values() {
        // Hack: We're assuming serialized size of the value is its in-memory size.
        // For ints of all flavors, this should be true.
        byte_len += core::mem::size_of::<K>();
        byte_len += core::mem::size_of::<V>();
    }

    (byte_len as u32).write_options(w, opts, args)?;
    let pos = w.stream_position()?;

    for (k, v) in s {
        k.write_options(w, opts, args)?;
        v.write_options(w, opts, args)?;
    }
    assert_eq!(w.stream_position()?, pos + byte_len as u64);
    Ok(())
}

fn parse_int_map<K, V, R>(reader: &mut R, ro: &ReadOptions, args: ()) -> BinResult<BTreeMap<K, V>>
where
    K: BinRead<Args = ()> + std::cmp::Ord,
    V: BinRead<Args = ()>,
    R: Read + Seek,
{
    let mut parsed = BTreeMap::new();

    // Length of the map in BYTES, not records.
    let byte_len: u32 = BinRead::read_options(reader, ro, args)?;
    let pos = reader.stream_position()?;

    while (reader.stream_position()? - pos) < byte_len as u64 {
        let k = K::read_options(reader, ro, args)?;
        let v = V::read_options(reader, ro, args)?;
        if let Some(_prev) = parsed.insert(k, v) {
            return Err(binrw::Error::Custom {
                pos,
                err: Box::new("Duplicate keys in map"),
            });
        }
    }

    Ok(parsed)
}

#[derive(Debug, BinRead, BinWrite)]
pub struct Channel {
    pub id: u16,
    pub schema_id: u16,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub topic: String,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub message_encoding: String,

    #[br(parse_with = parse_string_map)]
    #[bw(write_with = write_string_map)]
    pub metadata: BTreeMap<String, String>,
}

fn time_to_nanos(d: &SystemTime) -> u64 {
    let ns = d.duration_since(UNIX_EPOCH).unwrap().as_nanos();
    assert!(ns <= u64::MAX as u128);
    ns as u64
}

fn nanos_to_time(n: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(n)
}

#[derive(Debug, BinRead, BinWrite)]
pub struct MessageHeader {
    pub channel_id: u16,
    pub sequence: u32,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub log_time: SystemTime,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub publish_time: SystemTime,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct ChunkHeader {
    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub message_start_time: SystemTime,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub message_end_time: SystemTime,

    pub uncompressed_size: u64,

    pub uncompressed_crc: u32,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub compression: String,

    pub compressed_size: u64,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct MessageIndexEntry {
    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub log_time: SystemTime,

    pub offset: u64,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct MessageIndex {
    pub channel_id: u16,

    #[br(parse_with = parse_vec)]
    #[bw(write_with = write_vec)]
    pub records: Vec<MessageIndexEntry>,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct ChunkIndex {
    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub message_start_time: SystemTime,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub message_end_time: SystemTime,

    pub chunk_start_offset: u64,

    pub chunk_length: u64,

    #[br(parse_with = parse_int_map)]
    #[bw(write_with = write_int_map)]
    pub message_index_offsets: BTreeMap<u16, u64>,

    pub message_index_length: u64,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub compression: String,

    pub compressed_size: u64,

    pub uncompressed_size: u64,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct AttachmentHeader {
    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub log_time: SystemTime,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub create_time: SystemTime,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub name: String,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub content_type: String,

    pub data_len: u64,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct AttachmentIndex {
    pub offset: u64,

    pub length: u64,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub log_time: SystemTime,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub create_time: SystemTime,

    pub data_size: u64,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub name: String,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub content_type: String,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct Statistics {
    pub message_count: u64,
    pub schema_count: u16,
    pub channel_count: u32,
    pub attachment_count: u32,
    pub metadata_count: u32,
    pub chunk_count: u32,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub message_start_time: SystemTime,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    pub message_end_time: SystemTime,

    #[br(parse_with = parse_int_map)]
    #[bw(write_with = write_int_map)]
    pub message_index_offsets: BTreeMap<u16, u64>,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct Metadata {
    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub name: String,

    #[br(parse_with = parse_string_map)]
    #[bw(write_with = write_string_map)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct MetadataIndex {
    pub offset: u64,

    pub length: u64,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    pub name: String,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct SummaryOffset {
    pub group_opcode: u8,
    pub group_start: u64,
    pub group_length: u64,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct EndOfData {
    pub data_section_crc: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn string_parse() {
        let ms: McapString = Cursor::new(b"\x04\0\0\0abcd").read_le().unwrap();
        assert_eq!(
            ms,
            McapString {
                inner: String::from("abcd")
            }
        );

        assert!(Cursor::new(b"\x05\0\0\0abcd")
            .read_le::<McapString>()
            .is_err());

        let mut written = Vec::new();
        Cursor::new(&mut written)
            .write_le(&McapString {
                inner: String::from("hullo"),
            })
            .unwrap();
        assert_eq!(&written, b"\x05\0\0\0hullo");
    }

    #[test]
    fn header_parse() {
        let expected = b"\x04\0\0\0abcd\x03\0\0\0123";

        let h: Header = Cursor::new(expected).read_le().unwrap();
        assert_eq!(h.profile, "abcd");
        assert_eq!(h.library, "123");

        let mut written = Vec::new();
        Cursor::new(&mut written).write_le(&h).unwrap();
        assert_eq!(written, expected);
    }
}
