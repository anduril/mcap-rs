use binrw::*;
use binrw::io::{Read, Write, Seek};

use std::{collections::BTreeMap, time::{Duration, SystemTime, UNIX_EPOCH}};

#[binrw]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct McapString {
    #[br(temp)]
    #[bw(calc = inner.len() as u32)]
    len: u32,

    #[br(count = len, try_map = |s: Vec<u8>| String::from_utf8(s))]
    #[bw(map = |s| s.as_bytes())]
    inner: String
}

/// Avoids taking a copy to turn a String to an McapString for serialization
fn write_string<W: binrw::io::Write + binrw::io::Seek>(
    s: &String,
    w: &mut W,
    opts: &WriteOptions,
    args: ()) -> BinResult<()> {
    (s.len() as u32).write_options(w, opts, args)?;
    (s.as_bytes()).write_options(w, opts, args)?;
    Ok(())
}

#[binrw]
#[derive(Debug, Clone, Eq, PartialEq)]
struct McapVec {
    #[br(temp)]
    #[bw(calc = inner.len() as u32)]
    len: u32,

    #[br(count = len)]
    inner: Vec<u8>
}

/// Avoids taking a copy to turn a Vec to an McapVec for serialization
fn write_vec<W: binrw::io::Write + binrw::io::Seek, T: binrw::BinWrite<Args = ()>>(
    v: &Vec<T>,
    w: &mut W,
    opts: &WriteOptions,
    args: ()) -> BinResult<()> {
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
    profile: String,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    library: String,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct Footer {
    summary_start: u64,
    summary_offset_start: u64,
    summary_crc: u32,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct Schema {
    id: u16,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    name: String,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    encoding: String,

    #[br(map = |s: McapVec| s.inner )]
    #[bw(write_with = write_vec)]
    data: Vec<u8>
}

fn parse_map<R: Read + Seek>(reader: &mut R, ro: &ReadOptions, args: ())
    -> BinResult<BTreeMap<String, String>> {

    let mut parsed = BTreeMap::new();
    let len: u32 = BinRead::read_options(reader, ro, args)?;
    for _ in 0..len {
        let pos = reader.stream_position()?;
        let k = McapString::read_options(reader, ro, args)?;
        let v = McapString::read_options(reader, ro, args)?;
        if let Some(_prev) = parsed.insert(k.inner, v.inner) {
            return Err(binrw::Error::Custom { pos, err: Box::new("Duplicate keys in map")});
        }
    }

    Ok(parsed)
}

fn write_map<W: Write + Seek>(
    s: &BTreeMap<String, String>,
    w: &mut W,
    opts: &WriteOptions,
    args: ()) -> BinResult<()> {
    (s.len() as u32).write_options(w, opts, args)?;
    for (k, v) in s {
        write_string(k, w, opts, args)?;
        write_string(v, w, opts, args)?;
    }
    Ok(())
}

#[derive(Debug, BinRead, BinWrite)]
pub struct Channel {
    id: u16,
    schema_id: u16,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    topic: String,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    message_encoding: String,

    #[br(parse_with = parse_map)]
    #[bw(write_with = write_map)]
    metadata: BTreeMap<String, String>
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
    id: u16,
    sequence: u32,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    log_time: SystemTime,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    publish_time: SystemTime,
}

#[derive(Debug, BinRead, BinWrite)]
pub struct ChunkHeader {
    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    message_start_time: SystemTime,

    #[br(map = nanos_to_time)]
    #[bw(map = time_to_nanos)]
    message_end_time: SystemTime,

    uncompressed_size: u64,

    uncompressed_crc: u32,

    #[br(map = |s: McapString| s.inner )]
    #[bw(write_with = write_string)]
    compression: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn string_parse() {
        let ms: McapString = Cursor::new(b"\x04\0\0\0abcd").read_le().unwrap();
        assert_eq!(ms, McapString { inner: String::from("abcd") });

        assert!(Cursor::new(b"\x05\0\0\0abcd").read_le::<McapString>().is_err());

        let mut written = Vec::new();
        Cursor::new(&mut written).write_le(&McapString { inner: String::from("hullo") }).unwrap();
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