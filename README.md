# subdomain-recon

Subdomain enumeration by DNS brute force. Takes a domain and a wordlist,
resolves every `<word>.<domain>`, and filters out wildcard DNS so you don't
drown in false positives. Standard library only.

## Why I built this

Recon is step one of every pentest writeup I've read, and subdomain
enumeration is the most mechanical part of it — which made it a good
weekend project. I also specifically wanted to understand wildcard DNS,
because it's the classic gotcha: point a brute-forcer at a wildcarded
domain without handling it and every word in your list "resolves."
Thousands of results, all fake.

## What it does

- Builds candidates from a wordlist (`api.example.com`,
  `vpn.example.com`, ...) — 59 common labels bundled in `subdomains.txt`
- Detects wildcard DNS first: resolves 3 random, almost-certainly-fake
  hostnames. If they all resolve, the zone answers for anything, and any
  candidate that only hits those IPs gets thrown out
- Handles round-robin wildcards by taking the union of all probe answers
- Threaded lookups (default 20, configurable)
- Plain `host -> ip` output, or JSON with `--json`

## Usage

```bash
# basic run against a domain, using the bundled wordlist
python3 recon.py example.com

# custom wordlist, more threads, JSON output
python3 recon.py example.com --wordlist mywords.txt --threads 50 --json

# slower / lossy network? raise the per-lookup timeout
python3 recon.py example.com --timeout 10
```

### Options

| Flag          | Default            | Description                              |
|---------------|--------------------|------------------------------------------|
| `domain`      | (required)         | target domain, e.g. `example.com`        |
| `--wordlist`  | `./subdomains.txt` | wordlist file (blank lines / `#` ignored)|
| `--threads`   | `20`               | concurrent DNS lookups                   |
| `--json`      | off                | emit results as JSON                     |
| `--timeout`   | `5.0`              | per-lookup socket timeout (seconds)      |

### Sample output

Text mode:

```
$ python3 recon.py example.com --wordlist tiny.txt
www.example.com -> 93.184.216.34
[*] 1 of 5 candidates resolved
```

JSON mode:

```
$ python3 recon.py example.com --wordlist tiny.txt --json
[
  {
    "subdomain": "www.example.com",
    "ips": [
      "93.184.216.34"
    ]
  }
]
```

On a wildcarded domain you will see the filter kick in:

```
$ python3 recon.py wildcarded.example
[*] wildcard DNS detected (203.0.113.7); filtering false positives
[*] 0 of 62 candidates resolved
```

## Requirements

Python 3.8+. Nothing to install — see `requirements.txt`.

## What tripped me up

Testing. The sandbox I built this in has a DNS setup that answers
*everything* — even obvious garbage names resolve. So my first "successful"
test run reported the entire wordlist as live subdomains and I assumed the
wildcard filter was broken. It wasn't; the network was lying to me. I ended
up writing stubbed unit checks with a monkeypatched resolver to verify the
wildcard logic properly: no wildcard, plain wildcard, round-robin
wildcard, empty wordlist. All pass.

The other lesson: probe labels need to be long and random. A short label
like `test123` might actually exist on some domain, and then your wildcard
check gives you the wrong answer. Sixteen random characters won't collide
with anything real.

## What I'd do differently

- Async DNS instead of threads — cleaner at high concurrency.
- More record types. Right now it's A records only; TXT and MX can leak
  interesting stuff too.
- Passive sources (certificate transparency logs and the like) alongside
  brute-forcing. Active-only recon misses things.

## A note on using this

Only enumerate domains you own or have explicit written permission to
test — a bug bounty scope, a lab, your own stuff. Brute-forcing generates
real query traffic against someone's nameservers, so keep the thread count
and wordlist reasonable. Unauthorized scanning can get you in legal
trouble.
