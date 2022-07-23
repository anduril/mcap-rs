mod logsetup;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use log::*;
use memmap::Mmap;
use streaming_iterator::StreamingIterator;

#[derive(Parser, Debug)]
struct Args {
    /// Verbosity (-v, -vv, -vvv, etc.)
    #[clap(short, long, parse(from_occurrences))]
    verbose: u8,

    #[clap(short, long, arg_enum, default_value = "auto")]
    color: logsetup::Color,

    mcap: Utf8PathBuf
}

fn map_mcap(p: &Utf8Path) -> Result<Mmap> {
    let fd = std::fs::File::open(p).context("Couldn't open MCAP file")?;
    unsafe { Mmap::map(&fd) }.context("Couldn't map MCAP file")
}

fn run() -> Result<()> {
    let args = Args::parse();
    logsetup::init_logger(args.verbose, args.color);

    let mapped = map_mcap(&args.mcap)?;

    let mut records = mcap::LinearReader::new(&mapped)?;

    while let Some(record) = records.next() {
        println!("{:?}", record);
    }
    Ok(())
}

fn main() {
    run().unwrap_or_else(|e| {
        error!("{:?}", e);
        std::process::exit(1);
    });
}
