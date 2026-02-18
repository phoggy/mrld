use ansi_term::Colour::{Blue, Green, Red, Yellow};
use argh::FromArgs;
use std::io::{self, BufRead};
use serde_json::json;
use zxcvbn::{zxcvbn, Entropy};

const NAME: &'static str = "mrld";
const VERSION: &'static str = "0.1.0";

#[derive(FromArgs)]
/// A password/phrase strength estimator that, by default, outputs a simplified format
/// suitable for displaying alongside password/phrase input. The password/phrase is read
/// from stdin and must terminate with a newline character.
struct Args {
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
    return if args.version {
        version()
    } else {
        estimate(args)
    };
}

fn estimate(args: Args) -> Result<(), String> {
    let stdin = io::stdin();
    let pass = stdin.lock().lines().next().unwrap().unwrap();
    return match zxcvbn(&pass, &[]) {
        Ok(estimate) => {
            print(args, estimate);
            Ok(())
        }
        Err(e) => Err(format!("Error estimating strength: {e}")),
    };
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
        "10B_per_second": times.offline_fast_hashing_1e10_per_second().to_string()
    });
    *json.get_mut("crack_times").unwrap() = update;

    if args.multiline {
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!("{}", serde_json::to_string(&json).unwrap());
    }
}

fn print_summary(args: Args, estimate: Entropy) {
    let crack_time = estimate.crack_times().offline_slow_hashing_1e4_per_second();
    let score = estimate.score();
    let mut description = " to crack";
    let mut tally = format!("({score}/4)");
    let color;
    let name;
    let adjective;

    match score {
        0 | 1 => {
            color = Red.normal();
            name = "very weak";
        }
        2 => {
            color = Yellow.normal();
            name = "weak";
        }
        3 => {
            color = Blue.normal();
            name = "good";
        }
        4 => {
            color = Green.bold();
            name = "strong";
        }
        _ => panic!("unknown score value"),
    };

    if args.plain {
        adjective = name.to_string();
    } else {
        adjective = color.paint(name).to_string();
    }

    if args.multiline {
        if args.terse {
            tally = format!("\n{score}\n");
            description = "";
        } else {
            tally = format!("\n{tally}\n");
        }
    } else if args.terse {
        tally = format!(",{score},");
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
