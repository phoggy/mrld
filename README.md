# Password Strength Estimate

A command-line tool that uses [zxcvbn](https://github.com/shssoichiro/zxcvbn-rs) to report the estimated strength of a 
password/phrase, with the goal of encouraging or enforcing use of strong ones. 

A simplified form suitable for display during input is reported by default, following the [bitwarden](https://bitwarden.com/password-strength/) model:
- map the 0-4 score value to an adjective: < 2 = `very weak`, 2 =`weak`, 3 =`good`, 4 =`strong`
- use only the 10k/s 'offline attack, slow hash, many cores' crack time.


```bash
$ echo "my password" | emrld
very weak, 11 seconds to crack
```
The adjective is *colored* according to the score:
- 0 = red
- 1 = red
- 2 = yellow
- 3 = blue
- 4 = green (_mrld_)
                                                 
This can be disabled with the `--no-color` option:
```
Options:
  -p, --pretty      split output on multiple lines
  -s, --score       add score as an integer from 0 to 4
  -n, --no-color    do not use color
  -t, --terse       minimize output
  -v, --verbose     output complete estimate as JSON
  --version         output version information and exit
  --help            display usage information
```

Here's an example of the prettified verbose output:

```bash
$ echo "my password" | emrld --verbose --pretty
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
