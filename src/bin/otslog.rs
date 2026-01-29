use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::num::NonZero;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;
use std::thread::sleep;

use clap::{Parser, Subcommand};

use opentimestamps::timestamp::TimestampBuilder;
use opentimestamps::op::HashOp;
use opentimestamps::rpc;
use opentimestamps::timestamp::detached::{DetachedTimestampFile, FileDigest};

use rolling_timestamp::{Entry, Journal, JournalMut, IncrementalHasher};



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
    Extract(ExtractArgs),
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

#[derive(Parser, Debug)]
struct ExtractArgs {
    #[arg(name = "OFFSET", required = true)]
    offset: u64,

    #[arg(name = "FILE", required = true)]
    src_path: PathBuf,

    #[arg(name = "OTSLOG")]
    otslog_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    let _verbosity: isize = (args.verbose as isize) - (args.quiet as isize);

    dbg!(&args);

    match args.command {
        Command::Stamp(args) => stamp_command(args).await,
        Command::Extract(args) => extract_command(args).await,
    }
}

async fn stamp_command(args: StampArgs) -> Result<(), Box<dyn std::error::Error>> {
    let src_fd = File::open(&args.src_path)?;

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

    let mut hasher = if let Some(last_entry) = dbg!(otslog.last_entry()?) {
        IncrementalHasher::from_fd_at_idx(src_fd, last_entry.idx, last_entry.midstate)?
    } else {
        IncrementalHasher::new(src_fd)
    };

    /// Track when we last created a timestamp. This is used to throttle timestamp
    /// creation according to --follow duration, avoiding excessive API calls when
    /// the source file is being written to rapidly.
    let mut last_stamp_time = Instant::now();

    loop {
        match hasher.hash_next_chunk() {
            Ok(Some((midstate, digest, idx))) => {
                /// New data was hashed. Only create a timestamp if sufficient time
                /// has passed since the last one. This batches rapid writes into
                /// periodic timestamps rather than one per chunk.
                if last_stamp_time.elapsed() < args.follow {
                    continue;
                }

                let nonce: [u8; 16] = rand::random();
                let ts = TimestampBuilder::new(digest)
                                          .append(&nonce[..])
                                          .hash(HashOp::Sha256);

                let digest: [u8; 32] = ts.result().try_into().expect("sha256 output is 32 bytes");

                let digest_ts = rpc::stamp_with_options(digest, Default::default()).await?;

                let (midstate, _) = midstate.to_parts();
                let entry = Entry::new(idx, midstate, ts.finish_with_timestamps([digest_ts]));  
                otslog.write_entry(&entry)?;

                last_stamp_time = Instant::now();
            },
            Ok(None) => {
                /// Reached end of file. If --follow is non-zero, sleep and poll
                /// for new data. Otherwise, we're done.
                if args.follow.as_secs() > 0 {
                    sleep(Duration::from_millis(1000));
                } else {
                    break;
                }
            },
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

async fn extract_command(args: ExtractArgs) -> Result<(), Box<dyn std::error::Error>> {
    let src_fd = File::open(&args.src_path)?;

    let otslog_path = args.otslog_path.unwrap_or_else(||{
        let mut p = args.src_path.clone();
        p.add_extension("otslog");
        p
    });

    let otslog = Journal::open(&otslog_path)?;

    if let Some(entry) = otslog.get_entry(args.offset)? {
        let truncated_src_path = args.src_path.with_added_extension(args.offset.to_string());
        let mut truncated_src_fd = OpenOptions::new()
                                               .create_new(true)
                                               .write(true)
                                               .open(&truncated_src_path)?;

        let written = io::copy(&mut src_fd.take(entry.idx), &mut truncated_src_fd)?;
        assert_eq!(written, entry.idx); // TODO: how should we handle this?

        let truncated_src_ots_path = dbg!(dbg!(truncated_src_path).with_added_extension("ots"));
        let mut truncated_src_ots_fd = OpenOptions::new()
                                                   .create_new(true)
                                                   .write(true)
                                                   .open(&truncated_src_ots_path)?;

        let ts_proof = entry.timestamp.map_msg(|digest|
            FileDigest::Sha256(digest.to_byte_array())
        );
        let detached_ts_proof = DetachedTimestampFile::new(ts_proof);

        detached_ts_proof.serialize(&mut truncated_src_ots_fd)?;
    } else {
        panic!("out of range");
    }

    Ok(())
}
