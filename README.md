# Password Strength Estimation

A command-line tool that uses [zxcvbn](https://github.com/shssoichiro/zxcvbn-rs) to report the estimated strength of a
password/phrase, with the goal of encouraging and/or enforcing use of strong ones.

A simplified form is reported by default, following the [bitwarden](https://bitwarden.com/password-strength/) model:
- map the 0-4 score value to an adjective:
  - 0,1 &rarr; "very weak", 2 &rarr; "weak", 3 &rarr; "good", 4 &rarr; "strong"
- color the adjective to indicate desirability:
  - "very weak" &rarr; red, "weak" &rarr; yellow, "good" &rarr; blue, "strong" &rarr; green (_"mrld"_)
- judge the score, and report a crack time, against one specific scenario - selected via `--use-case` and
  `--threat-level` (see below)

Options

```
  -u, --use-case    which use case to estimate crack time for: 'account' (a
                    service whose password hashing you don't control) or 'file'
                    (an Age-encrypted file/private key, at Age's default scrypt
                    work factor) (default: account)
  -l, --threat-level
                    how much guessing power to judge the strength verdict
                    against: 'casual', 'motivated', 'professional', or
                    'nation-state' (default: professional)
  -m, --multi-line  split output on multiple lines
  -n, --no-color    do not use color
  -t, --terse       minimize output
  -v, --verbose     output entire estimate as JSON
  --version         output version information
  --help            display usage information
```

Example (adjective is not colored here)

```bash
$ echo "my password" | mrld
very weak (1/4) against professional attacker on account, 11 seconds to crack
```

Here's an example of verbose, multi-line output:

```bash
$ echo "my password" | mrld --verbose --multi-line
{
  "guesses": 110000,
  "guesses_log10": 5.041392685158225,
  "crack_times": {
    "100_per_hour": "1 month",
    "10_per_second": "3 hours",
    "10k_per_second": "11 seconds",
    "10B_per_second": "less than a second",
    "age_scrypt_1_core": "1 day",
    "age_scrypt_32_cores": "57 minutes",
    "age_scrypt_128_cores": "14 minutes",
    "age_scrypt_1024_cores": "1 minute",
    "age_scrypt_100000_cores": "1 second"
  },
  "score": 1,
  "feedback": {
    "warning": "ThisIsSimilarToACommonlyUsedPassword",
    "suggestions": [
      "AddAnotherWordOrTwo"
    ]
  },
  "sequence": [ ... ],
  "calc_time": { "secs": 0, "nanos": 13714110 },
  "use_case": "account",
  "threat_level": "professional",
  "level": 1,
  "description": "very weak",
  "report": [
    {
      "time": "1 month",
      "actor": "for casual attacker",
      "detail": "throttled online attack",
      "primary": false
    },
    {
      "time": "3 hours",
      "actor": "for motivated attacker",
      "detail": "unthrottled online attack",
      "primary": false
    },
    {
      "time": "11 seconds",
      "actor": "if the account is breached and uses slow hashing",
      "detail": "a few GPUs",
      "primary": true
    },
    {
      "time": "less than a second",
      "actor": "if the account is breached and uses fast hashing",
      "detail": "a single GPU",
      "primary": true
    }
  ]
}
```

`crack_times` lists every built-in scenario for full transparency, regardless of `--use-case`. `report` is the
subset relevant to the selected `--use-case`, each entry naming which attacker tier it represents; `primary` marks
the entry (or entries, when hash choice rather than attacker capability is what's actually undetermined) that
`level`/`description` were computed against.

### Use cases and threat levels

`--use-case` picks which family of attack scenarios apply:

- `account` - a password protecting an account on a service whose password hashing you don't control: online
  login attempts (throttled and unthrottled) plus offline cracking if the account's password database is ever
  breached, split by whether that service hashes passwords slowly (e.g. bcrypt/scrypt) or quickly (e.g. unsalted
  MD5/SHA1).
- `file` - a password/passphrase protecting an Age-encrypted file or private key, cracked offline at Age's default
  scrypt work factor, across a range of attacker compute (1 to 100,000 cores).

`--threat-level` picks which attacker capability the strength verdict (`level`/`description`, and hence "safe to
use") is judged against - `casual` < `motivated` < `professional` < `nation-state`, in ascending guessing power.
The same threat-level vocabulary means the same real capability regardless of `--use-case`: e.g. `professional`
means the same guesses/hour whether you asked about `account` or `file`, even though the underlying scenario
(a few GPUs vs. many CPU cores) looks different.

### Methodology and sources

mrld reports two independent things: how *guessable* a password is, and how long that translates to at a given
guessing rate. Both draw on real sources where one exists; where mrld had to make its own modeling choice, that's
called out explicitly rather than presented with the same authority.

**Guess counts** come from the [zxcvbn](https://github.com/shssoichiro/zxcvbn-rs) algorithm (Wheeler, D.L.,
["zxcvbn: Low-Budget Password Strength Estimation,"](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler)
USENIX Security Symposium, 2016), via the `zxcvbn` Rust crate. Guesses are pattern-based (dictionary words, l33t
substitutions, dates, keyboard walks, repeats, sequences) rather than raw character-set entropy, which is what
makes it a meaningfully better estimator than naive entropy calculations - it approximates how real cracking
tools actually search, not a uniform-random upper bound.

**mrld's displayed score is not zxcvbn's own score, and the two will disagree.** `zxcvbn` (and tools built
directly on it, like the [zxcvbn-ts demo](https://zxcvbn-ts.github.io/zxcvbn/demo/)) report a 0-4 score derived
from `guesses_log10` alone - fixed buckets regardless of who's attacking or how fast. mrld exposes that same
value too (the `score` field in `--verbose` output, for reference), but the `level`/`description` it actually
reports - what drives the "very weak"/"weak"/"good"/"strong" adjective - is a different, deliberately redesigned
metric: crack time under the one specific scenario `--use-case`/`--threat-level` selected, bucketed by real-world
duration (`<1 day`, `<90 days`, `<10 years`, else). The two frequently diverge. For example, `bob barker17`
judged as `account`/`casual` has `guesses_log10 ≈ 8.98` - zxcvbn's own score is 3 ("good"), matching what the
zxcvbn-ts demo shows - but at a *casual* attacker's rate (100 guesses/hour, throttled online), those ~961 million
guesses take over 1,000 years, which crosses mrld's own `>10 years` threshold: `level` 4 ("strong"). Both tools
agree on how guessable the password is; they disagree on what to do with that number, because mrld deliberately
answers a narrower, more concrete question - how long would *this* attacker actually take - rather than reporting
a generic, scenario-agnostic bucket.

**`account`'s four base rates** - 100/hour (throttled online), 10/second (unthrottled online), 10,000/second
(offline, slow hash), and 10,000,000,000/second (offline, fast hash) - are `zxcvbn`'s own built-in reference
rates for these scenarios, not values mrld invented.

**`file`'s per-core baseline** (~1 guess/second/core) comes from Age's own documented scrypt work factor
(`log2(N)=18`): see [`scrypt.go`](https://github.com/FiloSottile/age/blob/main/scrypt.go) in the Age source.

**mrld's own modeling assumptions**, not independently sourced or validated:
- `file`'s multi-core/cluster tiers (32, 128, 1024, 100,000 cores) scale that per-core baseline linearly. The
  100,000-core tier assumes roughly 25.6TB of RAM in flight at once (100,000 &times; scrypt's ~256MB/guess at
  this work factor) - a real cost, offered as a plausible ceiling for nation-state-scale resourcing against a
  memory-hard hash, not a measured figure.
- The `casual`/`motivated`/`professional`/`nation-state` guessing-rate thresholds are mrld's own convention for
  grouping rates into a comparable vocabulary across both use cases - useful for relative comparison, not drawn
  from a published standard.

## Prerequisites

Requires [Nix](https://nixos.org/).

**Mac with Apple silicon:** Download and run the [Determinate Nix installer](https://dtr.mn/determinate-nix).

**Mac x86:**

```bash
curl -L https://nixos.org/nix/install | sh
```

**Linux:**

```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

All installers create a `/nix` volume and take a few minutes to complete. Answer yes to any
prompts and allow any system dialogs that pop up. Once complete, open a new terminal before
continuing.

If you used the Mac x86 installer, enable flakes:

```bash
mkdir -p ~/.config/nix
echo 'experimental-features = nix-command flakes' >> ~/.config/nix/nix.conf
```

## Installation

```bash
nix profile add github:phoggy/mrld
```

To run without installing:

```bash
nix run github:phoggy/mrld
```

Or check this project's GitHub Releases page for binaries.

## Developers

This project uses [cargo-dist](https://opensource.axo.dev/cargo-dist/) to create releases.
