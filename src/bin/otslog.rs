use std::fs::{File, OpenOptions};
use std::io;
use std::num::NonZero;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

use opentimestamps::timestamp::TimestampBuilder;
use opentimestamps::op::HashOp;
use opentimestamps::rpc;
use opentimestamps::timestamp::detached::{DetachedTimestampFile, FileDigest};

use rolling_timestamp::{Entry, JournalMut, IncrementalHasher};

fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseFloatError> {
    let seconds = arg.parse()?;
    Ok(Duration::from_secs_f64(seconds))
}

#[derive(Parser, Debug)]
struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count)]
    quiet: u8,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Stamp(StampArgs),
}

#[derive(Parser, Debug)]
struct StampArgs {
    #[arg(name = "FILE", required = true)]
    src_path: PathBuf,

    #[arg(name = "OTSLOG")]
    otslog_path: Option<PathBuf>,

    #[arg(short, long, name = "AGGREGATOR")]
    aggregators: Vec<String>,

    /// Timeout (seconds)
    #[arg(long, value_parser = parse_duration, default_value = "5.0")]
    timeout: Duration,

    /// Consider the timestamp complete if we get at least M attestations prior to the timeout
    #[arg(short, name = "M", default_value = "2")]
    min_attestations: NonZero<usize>,

    // Follow changes in the file, creating a new timestamp periodically if new data is written.
    #[arg(long, value_parser = parse_duration, default_value = "600")]
    follow: Duration,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    let _verbosity: isize = (args.verbose as isize) - (args.quiet as isize);

    dbg!(&args);

    match args.command {
        Command::Stamp(args) => stamp_command(args).await,
    }
}

async fn stamp_command(args: StampArgs) -> Result<(), Box<dyn std::error::Error>> {
    let src_fd = File::open(&args.src_path)?;
    let mut hasher = IncrementalHasher::new(src_fd);

    let otslog_path = args.otslog_path.unwrap_or_else(||{
        let mut p = args.src_path.clone();
        p.add_extension("otslog");
        p
    });

    let mut otslog = match JournalMut::open(&otslog_path) {
        Ok(otslog) => otslog,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            JournalMut::create(&otslog_path)?
        },
        Err(err) => { return Err(err.into()); },
    };

    let entry = loop {
        if let Some((midstate, digest, idx)) = dbg!(hasher.hash_next_chunk()?) {
            let nonce: [u8; 16] = rand::random();
            let mut ts = TimestampBuilder::new(digest)
                                      .append(&nonce[..])
                                      .hash(HashOp::Sha256);

            let digest: [u8; 32] = ts.result().try_into().expect("sha256 output is 32 bytes");

            let digest_ts = rpc::stamp_with_options(digest, Default::default()).await?;

            let (midstate, _) = midstate.to_parts();
            break Entry::new(idx, midstate, ts.finish_with_timestamps([digest_ts]))
        };
    };

    otslog.write_entry(&entry)?;

    Ok(())
}
