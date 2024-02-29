# Password Strength Estimation

A command-line tool that uses [zxcvbn](https://github.com/shssoichiro/zxcvbn-rs) to report the estimated strength of a 
password/phrase, with the goal of encouraging and/or enforcing use of strong ones. 

A simplified form is reported by default, following the [bitwarden](https://bitwarden.com/password-strength/) model:
- map the 0-4 score value to an adjective: 
  - 0,1 &rarr; "very weak", 2 &rarr; "weak", 3 &rarr; "good", 4 &rarr; "strong"
- color the adjective to indicate desirability: 
  - "very weak" &rarr; red, "weak" &rarr; yellow, "good" &rarr; blue, "strong" &rarr; green (_"mrld"_)
- use only the 10k/s "offline attack, slow hash, many cores" crack time

Options

```
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
very weak (0/4) - 11 seconds to crack
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
    "10B_per_second": "less than a second"
  },
  "score": 1,
  "feedback": {
    "warning": "ThisIsSimilarToACommonlyUsedPassword",
    "suggestions": [
      "AddAnotherWordOrTwo"
    ]
  },
  "sequence": [
    {
      "i": 0,
      "j": 2,
      "token": "my ",
      "pattern": "bruteforce",
      "guesses": 1000
    },
    {
      "i": 3,
      "j": 10,
      "token": "password",
      "pattern": "dictionary",
      "matched_word": "password",
      "rank": 2,
      "dictionary_name": "Passwords",
      "reversed": false,
      "l33t": false,
      "sub": null,
      "sub_display": null,
      "uppercase_variations": 1,
      "l33t_variations": 1,
      "base_guesses": 2,
      "guesses": 50
    }
  ],
  "calc_time": {
    "secs": 0,
    "nanos": 118927000
  }
}
```

## Installation

Check this project's GitHub Releases page for binaries.

## Developers

This project uses [cargo-dist](https://opensource.axo.dev/cargo-dist/) to create releases. 

