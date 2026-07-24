use ansi_term::Colour::{Blue, Green, Red, Yellow};
use ansi_term::Style;
use argh::FromArgs;
use std::io::{self, BufRead};
use std::time::Duration;
use serde_json::json;
use zxcvbn::time_estimates::CrackTimeSeconds;
use zxcvbn::{zxcvbn, Entropy};

const NAME: &str = "mrld";
const VERSION: &str = "0.1.1";

#[derive(FromArgs)]
/// A password/phrase strength estimator that, by default, outputs a simplified format
/// suitable for displaying alongside password/phrase input. The password/phrase is read
/// from stdin and must terminate with a newline character.
struct Args {
    /// estimate crack time against Age's scrypt work factor (~1 guess/second on a
    /// single core) instead of the generic offline-slow-hashing assumption
    #[argh(switch, long = "age", short = 'a')]
    age: bool,

    /// split output on multiple lines
    #[argh(switch, long = "multi-line", short = 'm')]
    multiline: bool,

    /// do not use color
    #[argh(switch, long = "no-color", short = 'n')]
    plain: bool,

    /// minimize output
    #[argh(switch, long = "terse", short = 't')]
    terse: bool,

    /// output entire estimate as JSON
    #[argh(switch, long = "verbose", short = 'v')]
    verbose: bool,

    /// output version information
    #[argh(switch, long = "version")]
    version: bool,
}

fn main() -> Result<(), String> {
    let args: Args = argh::from_env();
    if args.version {
        version()
    } else {
        estimate(args)
    }
}

fn estimate(args: Args) -> Result<(), String> {
    let stdin = io::stdin();
    let pass = stdin.lock().lines().next().unwrap().unwrap();
    let estimate = zxcvbn(&pass, &[]);
    print(args, estimate);
    Ok(())
}

fn print(args: Args, estimate: Entropy) {
    if args.verbose {
        print_verbose(args, estimate);
    } else {
        print_summary(args, estimate);
    }
}

fn print_verbose(args: Args, estimate: Entropy) {
    let mut json = serde_json::to_value(&estimate).expect("json serialization failed");

    // Edit result to replace "crack_times":{"guesses":110000} with calculated values

    let times = estimate.crack_times();
    let update = json!({
        "100_per_hour": times.online_throttling_100_per_hour().to_string(),
        "10_per_second": times.online_no_throttling_10_per_second().to_string(),
        "10k_per_second": times.offline_slow_hashing_1e4_per_second().to_string(),
        "10B_per_second": times.offline_fast_hashing_1e10_per_second().to_string(),
        "age_scrypt_1_per_second": age_scrypt_crack_time(estimate.guesses()).to_string()
    });
    *json.get_mut("crack_times").unwrap() = update;

    if args.multiline {
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!("{}", serde_json::to_string(&json).unwrap());
    }
}

/// Age's default scrypt work factor (log2(N)=18) is calibrated to take about one
/// second per guess on a single core: https://github.com/FiloSottile/age/blob/main/scrypt.go
const AGE_SCRYPT_GUESSES_PER_SECOND: f64 = 1.0;

fn age_scrypt_crack_time(guesses: u64) -> CrackTimeSeconds {
    CrackTimeSeconds::Float(guesses as f64 / AGE_SCRYPT_GUESSES_PER_SECOND)
}

/// Rates a crack-time estimate on a 1-4 scale, rather than using the raw zxcvbn score,
/// since the score's buckets are wide enough that e.g. "1 day to crack" and "centuries
/// to crack" both land in the same bucket. Keeping the displayed number and label tied
/// to the same classification avoids showing something like "weak (3/4)".
fn describe(crack_time: CrackTimeSeconds) -> (u8, &'static str, Style) {
    const DAY: u64 = 60 * 60 * 24;
    const NINETY_DAYS: u64 = DAY * 90;
    const TEN_YEARS: u64 = DAY * 365 * 10;

    let seconds = Duration::from(crack_time).as_secs();
    if seconds < DAY {
        (1, "very weak", Red.normal())
    } else if seconds < NINETY_DAYS {
        (2, "weak", Yellow.normal())
    } else if seconds < TEN_YEARS {
        (3, "good", Blue.normal())
    } else {
        (4, "strong", Green.bold())
    }
}

fn print_summary(args: Args, estimate: Entropy) {
    let crack_time = if args.age {
        age_scrypt_crack_time(estimate.guesses())
    } else {
        estimate.crack_times().offline_slow_hashing_1e4_per_second()
    };
    let (level, name, color) = describe(crack_time);
    let mut description = " to crack";
    let mut tally = format!("({level}/4)");
    let adjective;

    if args.plain {
        adjective = name.to_string();
    } else {
        adjective = color.paint(name).to_string();
    }

    if args.multiline {
        if args.terse {
            tally = format!("\n{level}\n");
            description = "";
        } else {
            tally = format!("\n{tally}\n");
        }
    } else if args.terse {
        tally = format!(",{level},");
        description = "";
    } else {
        tally = format!(" {tally}, ");
    }

    println!("{adjective}{tally}{crack_time}{description}");
}

fn version() -> Result<(), String> {
    println!("{NAME} {VERSION}");
    Ok(())
}
