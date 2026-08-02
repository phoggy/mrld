use ansi_term::Colour::{Blue, Green, Red, Yellow};
use ansi_term::Style;
use argh::FromArgs;
use serde::Serialize;
use serde_json::json;
use std::io::{self, BufRead};
use std::str::FromStr;
use zxcvbn::{zxcvbn, Entropy};

const NAME: &str = "mrld";
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which use case to estimate crack time for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UseCase {
    /// A service whose password hashing you don't control (online + generic offline
    /// scenarios).
    Account,
    /// An Age-encrypted file or private key, at Age's default scrypt work factor.
    File,
}

impl UseCase {
    fn label(self) -> &'static str {
        match self {
            UseCase::Account => "account",
            UseCase::File => "file",
        }
    }
}

impl FromStr for UseCase {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "account" => Ok(UseCase::Account),
            "file" => Ok(UseCase::File),
            _ => Err(format!("unknown use case: '{s}' (expected 'account' or 'file')")),
        }
    }
}

/// How much guessing power the caller wants the strength verdict (level/description, and
/// hence the safe/unsafe gate) judged against. Also used, per-scenario, to label each
/// crack-time report entry - see ThreatLevel::from_rate.
///
/// Declared in ascending order so the derived Ord matches real attacker capability: this is
/// relied on by primary_scenario's "pick the strongest scenario at or below the requested
/// level" selection.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ThreatLevel {
    Casual,
    Motivated,
    Determined,
    StateLevel,
}

impl ThreatLevel {
    /// Classifies a guess rate into a threat level, via one shared threshold table used for
    /// every crack-time scenario regardless of use case, so e.g. 1024 cores of scrypt (1024
    /// guesses/sec) and a 10B/sec fast-hash attack aren't both called "state-level" despite
    /// differing by seven orders of magnitude. Thresholds are guesses/second < 1 / 1-100 /
    /// 100-100k / >= 100k, expressed here in guesses/hour (x3600) to keep every comparison
    /// integer-only.
    fn from_rate(guesses_per_hour: u64) -> Self {
        if guesses_per_hour < 3_600 {
            ThreatLevel::Casual
        } else if guesses_per_hour < 360_000 {
            ThreatLevel::Motivated
        } else if guesses_per_hour < 360_000_000 {
            ThreatLevel::Determined
        } else {
            ThreatLevel::StateLevel
        }
    }

    fn label(self) -> &'static str {
        match self {
            ThreatLevel::Casual => "casual",
            ThreatLevel::Motivated => "motivated",
            ThreatLevel::Determined => "determined",
            ThreatLevel::StateLevel => "state-level",
        }
    }

    fn actor(self) -> String {
        format!("for {} attacker", self.label())
    }
}

impl FromStr for ThreatLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "casual" => Ok(ThreatLevel::Casual),
            "motivated" => Ok(ThreatLevel::Motivated),
            "determined" => Ok(ThreatLevel::Determined),
            "state-level" => Ok(ThreatLevel::StateLevel),
            _ => Err(format!(
                "unknown threat level: '{s}' (expected 'casual', 'motivated', 'determined', or 'state-level')"
            )),
        }
    }
}

#[derive(FromArgs)]
/// A password/phrase strength estimator that, by default, outputs a simplified format
/// suitable for displaying alongside password/phrase input. The password/phrase is read
/// from stdin and must terminate with a newline character.
struct Args {
    /// which use case to estimate crack time for: 'account' (a service whose password
    /// hashing you don't control) or 'file' (an Age-encrypted file/private key, at Age's
    /// default scrypt work factor) (default: account)
    #[argh(option, long = "use-case", short = 'u', default = "UseCase::Account")]
    use_case: UseCase,

    /// how much guessing power to judge the strength verdict against: 'casual', 'motivated',
    /// 'determined', or 'state-level' (default: determined)
    #[argh(option, long = "threat-level", short = 'l', default = "ThreatLevel::Determined")]
    threat_level: ThreatLevel,

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

/// A named crack-time scenario: a guess rate (expressed as guesses/hour so every scenario,
/// from a heavily throttled online login to a multi-core offline rig, is an integer, with no
/// special-casing for fractional guesses/second rates like 100/hour) plus how to describe it.
///
/// `actor_override`, when present, replaces the normal guesses/hour-derived attacker-type
/// label. It exists for account's offline pair: both scenarios need roughly the same (modest)
/// hardware, so what actually distinguishes them isn't attacker sophistication but the
/// account's own hash choice — labeling the fast-hash row "state-level attacker" would wrongly
/// imply a bigger, more capable adversary is required, when really any ordinary attacker gets
/// the same outcome once the account is breached.
struct Scenario {
    key: &'static str,
    guesses_per_hour: u64,
    detail: &'static str,
    actor_override: Option<&'static str>,
}

const ACCOUNT_SCENARIOS: &[Scenario] = &[
    Scenario {
        key: "100_per_hour",
        guesses_per_hour: 100,
        detail: "throttled online attack",
        actor_override: None,
    },
    Scenario {
        key: "10_per_second",
        guesses_per_hour: 36_000,
        detail: "unthrottled online attack",
        actor_override: None,
    },
    Scenario {
        key: "10k_per_second",
        guesses_per_hour: 36_000_000,
        detail: "a few GPUs",
        actor_override: Some("if the account is breached and uses slow hashing"),
    },
    Scenario {
        key: "10B_per_second",
        guesses_per_hour: 36_000_000_000_000,
        detail: "a single GPU",
        actor_override: Some("if the account is breached and uses fast hashing"),
    },
];

/// Age's default scrypt work factor (log2(N)=18) is calibrated to take about one second per
/// guess on a single core: https://github.com/FiloSottile/age/blob/main/scrypt.go
/// Scrypt's memory-hardness (~256MB per guess at this work factor) makes parallelizing
/// expensive relative to a fast hash, but not impossible for a well-resourced attacker
/// willing to spend on RAM - hence the multiple core-count scenarios.
const FILE_SCENARIOS: &[Scenario] = &[
    Scenario {
        key: "age_scrypt_1_core",
        guesses_per_hour: 3_600,
        detail: "offline attack, scrypt hash, single core",
        actor_override: None,
    },
    Scenario {
        key: "age_scrypt_32_cores",
        guesses_per_hour: 115_200,
        detail: "offline attack, scrypt hash, 32 cores",
        actor_override: None,
    },
    Scenario {
        key: "age_scrypt_128_cores",
        guesses_per_hour: 460_800,
        detail: "offline attack, scrypt hash, 128 cores",
        actor_override: None,
    },
    Scenario {
        key: "age_scrypt_1024_cores",
        guesses_per_hour: 3_686_400,
        detail: "offline attack, scrypt hash, 1024 cores",
        actor_override: None,
    },
];

fn scenarios_for(use_case: UseCase) -> &'static [Scenario] {
    match use_case {
        UseCase::Account => ACCOUNT_SCENARIOS,
        UseCase::File => FILE_SCENARIOS,
    }
}

/// The scenario driving the summary level/description and default crack-time display: the
/// strongest scenario in this use case's list whose own rate-derived threat level is at or
/// below the one requested, so "determined" means the same real guessing power for both use
/// cases (account's 10k_per_second; file's 1024-core scrypt) rather than an arbitrary,
/// separately-chosen scenario per use case. Scenarios are ordered weakest-to-strongest, so
/// this is exactly "keep walking forward while still within budget". Falls back to the
/// weakest scenario if even that already exceeds the requested level (e.g. 'casual' requested
/// for file, whose weakest tier - a single core - already rate-classifies as 'motivated').
fn primary_scenario(use_case: UseCase, threat_level: ThreatLevel) -> &'static Scenario {
    let scenarios = scenarios_for(use_case);
    let mut chosen = &scenarios[0];
    for scenario in scenarios {
        if ThreatLevel::from_rate(scenario.guesses_per_hour) <= threat_level {
            chosen = scenario;
        }
    }
    chosen
}

fn seconds_for(guesses: u64, guesses_per_hour: u64) -> u64 {
    // u128 to avoid overflow (guesses can approach u64::MAX; *3600 would not fit back in u64),
    // then saturate back into u64 - format_crack_time's largest threshold is far below u64::MAX
    // seconds, so any saturated value still correctly falls into its final "longer than the
    // age of the universe" bucket.
    let seconds = (guesses as u128 * 3600) / guesses_per_hour as u128;
    seconds.min(u64::MAX as u128) as u64
}

/// Formats a duration in seconds as a human-readable crack time. Matches zxcvbn's own
/// CrackTimeSeconds Display exactly for everything under ~1000 years (same MINUTE/HOUR/DAY/
/// MONTH/YEAR constants and pluralization), but - unlike zxcvbn, which collapses everything
/// past 100 years to the literal string "centuries" - keeps extending with human-graspable
/// units (thousand/million/billion years) instead of flattening wildly different multi-core
/// or multi-decade estimates into an identical, uninformative string.
fn format_crack_time(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = MINUTE * 60;
    const DAY: u64 = HOUR * 24;
    const MONTH: u64 = DAY * 31;
    const YEAR: u64 = MONTH * 12;
    const THOUSAND_YEARS: u64 = YEAR * 1_000;
    const MILLION_YEARS: u64 = YEAR * 1_000_000;
    const BILLION_YEARS: u64 = YEAR * 1_000_000_000;
    const AGE_OF_UNIVERSE_YEARS: u64 = 13_800_000_000;

    if seconds < 1 {
        "less than a second".to_string()
    } else if seconds < MINUTE {
        format!("{seconds} second{}", if seconds > 1 { "s" } else { "" })
    } else if seconds < HOUR {
        let base = seconds / MINUTE;
        format!("{base} minute{}", if base > 1 { "s" } else { "" })
    } else if seconds < DAY {
        let base = seconds / HOUR;
        format!("{base} hour{}", if base > 1 { "s" } else { "" })
    } else if seconds < MONTH {
        let base = seconds / DAY;
        format!("{base} day{}", if base > 1 { "s" } else { "" })
    } else if seconds < YEAR {
        let base = seconds / MONTH;
        format!("{base} month{}", if base > 1 { "s" } else { "" })
    } else if seconds < THOUSAND_YEARS {
        let base = seconds / YEAR;
        format!("{base} year{}", if base > 1 { "s" } else { "" })
    } else if seconds < MILLION_YEARS {
        format!("{} thousand years", seconds / THOUSAND_YEARS)
    } else if seconds < BILLION_YEARS {
        format!("{} million years", seconds / MILLION_YEARS)
    } else if seconds < AGE_OF_UNIVERSE_YEARS.saturating_mul(YEAR) {
        format!("{} billion years", seconds / BILLION_YEARS)
    } else {
        "longer than the age of the universe".to_string()
    }
}

#[derive(Serialize)]
struct ReportEntry {
    time: String,
    actor: String,
    detail: &'static str,
    /// True for the single entry representing primary_scenario's pick for the requested
    /// threat level - the one actually driving the summary's level/description/crack-time -
    /// so callers can highlight it instead of guessing which row matches by comparing labels.
    primary: bool,
}

/// Builds the use-case-aware crack-time report: one entry per scenario, with consecutive
/// scenarios that would share the same threat level collapsed into a single entry (the
/// higher-rate/worse-case one) so e.g. file's four core-count tiers - two of which land in the
/// same threat-level bucket under ThreatLevel::from_rate's thresholds - don't repeat the same
/// story twice. Scenarios with an actor_override are never collapsed: each already tells a
/// distinct, hash-choice-driven story regardless of rate.
///
/// The entry for `primary_key` (primary_scenario's pick) is never collapsed away, even when a
/// later same-level scenario would otherwise overwrite it - this matters for the fallback case
/// where the requested threat level is below every scenario's own rate-derived level (e.g.
/// 'casual' requested for file, whose weakest tier already rate-classifies as 'motivated'):
/// primary_scenario picks the weakest scenario, which would otherwise be silently merged into
/// a stronger same-level neighbor's row and vanish from the report entirely.
fn build_report(guesses: u64, scenarios: &[Scenario], primary_key: &str) -> Vec<ReportEntry> {
    let mut entries: Vec<ReportEntry> = Vec::new();
    let mut last_level: Option<ThreatLevel> = None;
    let mut last_is_primary = false;

    for scenario in scenarios {
        let time = format_crack_time(seconds_for(guesses, scenario.guesses_per_hour));
        let is_primary = scenario.key == primary_key;

        if let Some(actor) = scenario.actor_override {
            entries.push(ReportEntry { time, actor: actor.to_string(), detail: scenario.detail, primary: is_primary });
            last_level = None;
            last_is_primary = is_primary;
            continue;
        }

        let threat_level = ThreatLevel::from_rate(scenario.guesses_per_hour);
        let actor = threat_level.actor();
        if last_level == Some(threat_level) && !last_is_primary {
            *entries.last_mut().unwrap() = ReportEntry { time, actor, detail: scenario.detail, primary: is_primary };
        } else {
            entries.push(ReportEntry { time, actor, detail: scenario.detail, primary: is_primary });
        }
        last_level = Some(threat_level);
        last_is_primary = is_primary;
    }

    entries
}

fn print_verbose(args: Args, estimate: Entropy) {
    let mut json = serde_json::to_value(&estimate).expect("json serialization failed");
    let guesses = estimate.guesses();

    // Edit result to replace "crack_times":{"guesses":110000} with calculated values - all 8
    // scenarios, uncollapsed, for full transparency regardless of the selected use case.

    let mut crack_times = serde_json::Map::new();
    for scenario in ACCOUNT_SCENARIOS.iter().chain(FILE_SCENARIOS.iter()) {
        let time = format_crack_time(seconds_for(guesses, scenario.guesses_per_hour));
        crack_times.insert(scenario.key.to_string(), json!(time));
    }
    *json.get_mut("crack_times").unwrap() = serde_json::Value::Object(crack_times);

    // Add the same crack-time-based level/description used in the default summary output
    // (based on -u/--use-case and -l/--threat-level), so callers parsing --verbose don't have
    // to duplicate describe()'s thresholds themselves, plus the use-case-aware, collapsed
    // report - see build_report - which is what callers actually want to render per-scenario
    // detail from. use_case/threat_level are echoed back too since they determine what the
    // verdict actually means (e.g. "good" against a casual attacker is a different claim than
    // "good" against a state-level one).

    let primary = primary_scenario(args.use_case, args.threat_level);
    let (level, description, _color) = describe(seconds_for(guesses, primary.guesses_per_hour));
    let report = build_report(guesses, scenarios_for(args.use_case), primary.key);

    let obj = json.as_object_mut().unwrap();
    obj.insert("use_case".to_string(), json!(args.use_case.label()));
    obj.insert("threat_level".to_string(), json!(args.threat_level.label()));
    obj.insert("level".to_string(), json!(level));
    obj.insert("description".to_string(), json!(description));
    obj.insert("report".to_string(), json!(report));

    if args.multiline {
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!("{}", serde_json::to_string(&json).unwrap());
    }
}

/// Rates a crack-time estimate on a 1-4 scale, rather than using the raw zxcvbn score,
/// since the score's buckets are wide enough that e.g. "1 day to crack" and "centuries
/// to crack" both land in the same bucket. Keeping the displayed number and label tied
/// to the same classification avoids showing something like "weak (3/4)".
fn describe(seconds: u64) -> (u8, &'static str, Style) {
    const DAY: u64 = 60 * 60 * 24;
    const NINETY_DAYS: u64 = DAY * 90;
    const TEN_YEARS: u64 = DAY * 365 * 10;

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
    let guesses = estimate.guesses();
    let scenario = primary_scenario(args.use_case, args.threat_level);
    let seconds = seconds_for(guesses, scenario.guesses_per_hour);
    let crack_time = format_crack_time(seconds);
    let (level, name, color) = describe(seconds);
    let applied = ThreatLevel::from_rate(scenario.guesses_per_hour).label();
    let mut description = format!(" to crack ({applied} attacker)");
    let mut tally = format!("({level}/4)");
    let mut prefix = format!("{}/{}: ", args.use_case.label(), args.threat_level.label());
    let adjective;

    if args.plain {
        adjective = name.to_string();
    } else {
        adjective = color.paint(name).to_string();
    }

    if args.multiline {
        if args.terse {
            tally = format!("\n{level}\n");
            description = String::new();
            prefix = String::new();
        } else {
            tally = format!("\n{tally}\n");
        }
    } else if args.terse {
        tally = format!(",{level},");
        description = String::new();
        prefix = String::new();
    } else {
        tally = format!(" {tally}, ");
    }

    println!("{prefix}{adjective}{tally}{crack_time}{description}");
}

fn version() -> Result<(), String> {
    println!("{NAME} {VERSION}");
    Ok(())
}
