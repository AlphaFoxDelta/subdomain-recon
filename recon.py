#!/usr/bin/env python3
"""
Subdomain enumeration by DNS brute force. Stdlib only.

Builds <word>.<domain> candidates, resolves them, and filters wildcard DNS
so a wildcarded zone doesn't report your whole wordlist as "found".

    python3 recon.py example.com
"""

import argparse
import concurrent.futures
import json
import os
import random
import socket
import string
import sys

WILDCARD_PROBES = 3      # random probes for the wildcard check
RANDOM_LABEL_LEN = 16    # probe labels. long = won't collide with real names


def resolve_host(host):
    """Resolve a host to sorted unique IPs. None if it doesn't resolve."""
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return sorted(set(ips))
    except (socket.gaierror, socket.timeout, OSError):
        return None


def random_label(length=RANDOM_LABEL_LEN):
    """Random label for wildcard probes. 16 chars = won't exist."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def detect_wildcard(domain):
    """Check for wildcard DNS.

    Resolve a few random names. If they all resolve, the zone answers for
    anything — record those IPs so candidates hitting only them get dropped.
    Returns the wildcard IP set, or None when there's no wildcard.
    """
    wildcard_ips = set()
    for _ in range(WILDCARD_PROBES):
        ips = resolve_host("{}.{}".format(random_label(), domain))
        if ips is None:
            return None  # NXDOMAIN on a random name -> no wildcard
        wildcard_ips.update(ips)
    return wildcard_ips


def is_wildcard_hit(ips, wildcard_ips):
    """True if a candidate's IPs are all wildcard IPs."""
    return wildcard_ips is not None and set(ips) <= wildcard_ips


def check_candidate(candidate):
    """Resolve one candidate; return (candidate, ips or None)."""
    return candidate, resolve_host(candidate)


def load_wordlist(path):
    """One base word per line. Skip blanks and # comments."""
    words = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    return words


def parse_args(argv=None):
    default_wordlist = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "subdomains.txt"
    )
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate subdomains of a domain by resolving wordlist "
            "candidates via DNS, filtering wildcard-DNS false positives."
        )
    )
    parser.add_argument("domain", help="target domain, e.g. example.com")
    parser.add_argument(
        "--wordlist",
        default=default_wordlist,
        help="path to wordlist file (default: %(default)s)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=20,
        help="concurrent DNS lookups (default: %(default)s)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit results as JSON instead of plain text",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="per-lookup socket timeout in seconds (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    domain = args.domain.strip().lower().rstrip(".")
    socket.setdefaulttimeout(args.timeout)

    try:
        words = load_wordlist(args.wordlist)
    except OSError as exc:
        print("error: cannot read wordlist '{}': {}".format(args.wordlist, exc),
              file=sys.stderr)
        return 1
    if not words:
        print("error: wordlist '{}' is empty".format(args.wordlist),
              file=sys.stderr)
        return 1

    wildcard_ips = detect_wildcard(domain)
    if wildcard_ips is not None:
        print("[*] wildcard DNS detected ({}); filtering false positives"
              .format(", ".join(sorted(wildcard_ips))), file=sys.stderr)

    candidates = ["{}.{}".format(w, domain) for w in words]
    found = []
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=args.threads) as pool:
            futures = {pool.submit(check_candidate, c): c for c in candidates}
            for future in concurrent.futures.as_completed(futures):
                candidate, ips = future.result()
                if ips and not is_wildcard_hit(ips, wildcard_ips):
                    found.append((candidate, ips))
    except KeyboardInterrupt:
        print("\n[!] interrupted by user", file=sys.stderr)
        return 130

    found.sort()
    if args.json:
        print(json.dumps(
            [{"subdomain": sub, "ips": ips} for sub, ips in found], indent=2))
    else:
        for sub, ips in found:
            print("{} -> {}".format(sub, ", ".join(ips)))
        print("[*] {} of {} candidates resolved".format(len(found),
                                                         len(candidates)),
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
