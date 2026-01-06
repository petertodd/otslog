use std::num::NonZero;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

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
    src_file: PathBuf,

    #[arg(name = "OTSLOG")]
    otslog_file: Option<PathBuf>,

    #[arg(short, long, name = "AGGREGATOR")]
    aggregators: Vec<String>,

    /// Timeout (seconds)
    #[arg(long, value_parser = parse_duration, default_value = "5.0")]
    timeout: Duration,

    /// Consider the timestamp complete if we get at least M attestations prior to the timeout
    #[arg(short, name = "M", default_value = "2")]
    min_attestations: NonZero<usize>,

    // Follow changes in the file, creating a new timestamp periodically if new data is written.
    #[arg(long, value_parser = parse_duration, default_value = "5.0")]
    follow: Duration,
}

fn main() -> ExitCode {
    let args = Cli::parse();

    let _verbosity: isize = (args.verbose as isize) - (args.quiet as isize);

    dbg!(&args);

    match args.command {
        Command::Stamp(_args) => {
            todo!()
        },
    }

    //ExitCode::SUCCESS
}
