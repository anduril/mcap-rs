mod logsetup;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use log::*;
use memmap::Mmap;

#[derive(Parser, Debug)]
struct Args {
    /// Verbosity (-v, -vv, -vvv, etc.)
    #[clap(short, long, parse(from_occurrences))]
    verbose: u8,

    #[clap(short, long, arg_enum, default_value = "auto")]
    color: logsetup::Color,

    mcap: Utf8PathBuf,
}

fn map_mcap(p: &Utf8Path) -> Result<Mmap> {
    let fd = std::fs::File::open(p).context("Couldn't open MCAP file")?;
    unsafe { Mmap::map(&fd) }.context("Couldn't map MCAP file")
}

fn run() -> Result<()> {
    let args = Args::parse();
    logsetup::init_logger(args.verbose, args.color);

    let mapped = map_mcap(&args.mcap)?;

    for record in mcap::LinearReader::new(&mapped)? {
        let record = record?;
        println!("{:?}", record);
        if let mcap::Record::Chunk { header, data } = record {
            for chunk_record in mcap::ChunkReader::new(header, data)? {
                let chunk_record = chunk_record?;
                println!("\t{:?}", chunk_record);
            }
        }
    }
    Ok(())
}

fn main() {
    run().unwrap_or_else(|e| {
        error!("{:?}", e);
        std::process::exit(1);
    });
}
