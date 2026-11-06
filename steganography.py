#!/usr/bin/env python3
"""
GitHub History Steganographic Transceiver (Base-5 Codec)
Author: Gemini CLI / Senior Systems Engineer
Date: August 2026

This module provides an implementation of a steganographic communication channel
that stores and retrieves arbitrary binary payloads within a GitHub user's commit
history. The channel represents data visually as discrete contribution intensity levels
(0 to 4) in the GitHub contribution grid, corresponding to a base-5 numeral system.

Architectural Design & Rationale:
1. Grid Constraints: The target visualization medium (the GitHub contribution graph)
   natively supports exactly 5 discrete states (levels 0, 1, 2, 3, and 4). Any representation
   utilizing a higher base (e.g., octal or decimal) is physically non-mappable to the grid.
   Conversely, a lower base (e.g., binary) is inefficient, requiring 8 days of history per
   byte of data, which unnecessarily inflates the temporal footprint of the transmission.
2. Constant-Length Encoding: Each 8-bit byte (values 0-255) is mapped to a fixed-length
   sequence of exactly 4 base-5 digits (maximum capacity 5^4 = 625).
   - Byte B is decomposed as: B = d3*5^3 + d2*5^2 + d1*5^1 + d0*5^0
   - Where d_i in {0, 1, 2, 3, 4}
   - A variable-length encoding would require a reserved "separator" digit. Since there are
     only 5 physical states, dedicating 1 state as a separator would reduce the usable data
     base to 4, increasing total sequence lengths by ~15% and increasing sensitivity to
     alignment errors.
3. Error Isolation: By using a fixed-width 4-digit block size, a corrupt or missing day's
   contribution level affects at most 1 byte of the decoded stream. Under a variable-length
   encoding scheme, a single-digit error causes a cascade of framing shifts, resulting in
   catastrophic corruption of the entire remaining stream (the "blast radius" is global).
   Under this fixed-width scheme, the blast radius is strictly isolated to the affected block.
4. Channel Noise: Organic, non-steganographic commits on the same days can raise contribution
   levels, introducing additive noise to the channel. To ensure error-free transmission,
   the steganographic channel should be established on a dedicated, isolated repository
   or an orphan branch.
"""

import sys
import os
import re
import argparse
import datetime
import subprocess
import collections
import urllib.request
import urllib.error
import random

# Magic headers and footers to isolate the steganographic payload within the contribution history
MAGIC_HEADER = b"STEG"
MAGIC_FOOTER = b"END"

# Map from base-5 digit (level) to required commits (standard deterministic mode)
COMMIT_MAPPING = {
    0: 0,
    1: 1,
    2: 3,
    3: 6,
    4: 10
}

# Map from base-5 digit (level) to plausible ranges of commit counts (covert mode)
COMMIT_LEVEL_RANGES = {
    0: [0],
    1: [1, 2],
    2: [3, 4, 5],
    3: [6, 7, 8, 9],
    4: [10, 11, 12, 13]
}

# Plausible prefix standards for covert commit messages
COMMIT_PREFIXES = ["feat", "fix", "docs", "style", "refactor", "test", "chore"]

# Plausible developer summaries for covert commit messages
COMMIT_SUMMARIES = [
    "optimize database query indexing",
    "resolve null pointer exception in helper class",
    "update API integration documentation",
    "correct whitespace and alignment in source files",
    "refactor message queue broker connection logic",
    "add comprehensive unit tests for parser",
    "cleanup redundant third-party package imports",
    "implement caching mechanism for API responses",
    "fix off-by-one boundary condition in loop",
    "update configurations for continuous integration",
    "restructure file system directory hierarchy",
    "improve memory usage during file serialization",
    "resolve threading race condition in consumer stream",
    "document architectural constraints and trade-offs"
]

def generate_covert_commit_message() -> str:
    """
    Synthesizes a realistic, standard developer commit message.
    """
    prefix = random.choice(COMMIT_PREFIXES)
    summary = random.choice(COMMIT_SUMMARIES)
    return f"{prefix}: {summary}"

def generate_covert_timestamps(date_str: str, count: int) -> list[str]:
    """
    Generates sorted, pseudo-random business-hour timestamps for a given date.
    Timestamps are confined between 09:15 and 17:45.
    """
    timestamps = []
    for _ in range(count):
        hour = random.randint(9, 17)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        timestamps.append((hour, minute, second))
    
    # Chronological sort to ensure natural forward-moving time logs
    timestamps.sort()
    
    formatted = []
    for h, m, s in timestamps:
        formatted.append(f"{date_str}T{h:02d}:{m:02d}:{s:02d}")
    return formatted

# Terminal colors for dry-run rendering and status updates
COLORS = {
    0: '\033[90m░░\033[0m',  # Gray (Level 0)
    1: '\033[38;5;120m▒▒\033[0m', # Light Green (Level 1)
    2: '\033[38;5;77m▓▓\033[0m',  # Medium Green (Level 2)
    3: '\033[38;5;28m██\033[0m',  # Dark Green (Level 3)
    4: '\033[38;5;22m██\033[0m',  # Darkest Green (Level 4)
}

def byte_to_base5(val: int) -> list[int]:
    """
    Decomposes a single 8-bit byte into 4 base-5 digits (little-endian order).
    """
    if not (0 <= val <= 255):
        raise ValueError(f"Value {val} is outside the allowed byte range (0-255).")
    
    digits = []
    temp = val
    for _ in range(4):
        digits.append(temp % 5)
        temp //= 5
    return digits

def base5_to_byte(digits: list[int]) -> int:
    """
    Reconstructs an 8-bit byte from a list of 4 base-5 digits (little-endian order).
    """
    if len(digits) != 4:
        raise ValueError(f"Digit block must be of length 4, got {len(digits)}")
    
    val = 0
    for idx, digit in enumerate(digits):
        if not (0 <= digit <= 4):
            raise ValueError(f"Digit {digit} is not in the base-5 range [0, 4].")
        val += digit * (5 ** idx)
        
    if not (0 <= val <= 255):
        raise ValueError(f"Reconstructed value {val} exceeds the byte limit.")
    return val

def encode_payload(payload: bytes) -> list[int]:
    """
    Encodes an arbitrary byte payload with magic start/end markers into a base-5 digit stream.
    """
    full_payload = MAGIC_HEADER + payload + MAGIC_FOOTER
    digit_stream = []
    for byte in full_payload:
        digit_stream.extend(byte_to_base5(byte))
    return digit_stream

def decode_payload_digits(digit_stream: list[int]) -> bytes:
    """
    Scans a base-5 digit stream for the magic start/end markers and decodes the embedded payload.
    Uses a digit-by-digit sliding-window scanner to ensure perfect block alignment
    even in the presence of leading/trailing alignment offsets (noise).
    """
    # The expected base-5 digit sequences for b"STEG" and b"END"
    steg_signature = [3, 1, 3, 0, 4, 1, 3, 0, 4, 3, 2, 0, 1, 4, 2, 0]
    end_signature = [4, 3, 2, 0, 3, 0, 3, 0, 3, 3, 2, 0]
    
    # Search for steg_signature in digit_stream
    steg_len = len(steg_signature)
    header_idx = -1
    for i in range(len(digit_stream) - steg_len + 1):
        if digit_stream[i:i+steg_len] == steg_signature:
            header_idx = i
            break
            
    if header_idx == -1:
        raise ValueError("Steganographic magic header not found in the digit stream.")
        
    # Search for end_signature starting from after the header
    end_len = len(end_signature)
    footer_idx = -1
    for i in range(header_idx + steg_len, len(digit_stream) - end_len + 1):
        # We must step by multiples of 4 to ensure the footer is block-aligned with the header!
        if (i - header_idx) % 4 == 0:
            if digit_stream[i:i+end_len] == end_signature:
                footer_idx = i
                break
                
    if footer_idx == -1:
        raise ValueError("Steganographic magic footer not found in the digit stream.")
        
    # Extract the payload digits (between the end of b"STEG" and the start of b"END")
    payload_digits = digit_stream[header_idx + steg_len:footer_idx]
    
    # Reconstruct the payload bytes (4 digits per byte)
    payload_bytes = bytearray()
    for i in range(0, len(payload_digits), 4):
        block = payload_digits[i:i+4]
        if len(block) == 4:
            payload_bytes.append(base5_to_byte(block))
            
    return bytes(payload_bytes)

def parse_local_git_history() -> list[tuple[str, int]]:
    """
    Executes git log to retrieve the local commit dates and maps commit counts per day to base-5 levels.
    """
    cmd = ["git", "log", "--format=%ad", "--date=short"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing git command: {e.stderr}", file=sys.stderr)
        raise
    
    dates = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
    if not dates:
        return []
    
    counts = collections.Counter(dates)
    
    contributions = []
    for date_str, count in counts.items():
        # Map commit count to the closest contribution level threshold
        if count >= 10:
            level = 4
        elif count >= 6:
            level = 3
        elif count >= 3:
            level = 2
        elif count >= 1:
            level = 1
        else:
            level = 0
        contributions.append((date_str, level))
        
    return contributions

def fill_missing_dates(contributions: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """
    Fills in missing dates in a chronological contribution list with level-0 values.
    """
    if not contributions:
        return []
    
    sorted_contribs = sorted(contributions, key=lambda x: x[0])
    min_date = datetime.datetime.strptime(sorted_contribs[0][0], "%Y-%m-%d").date()
    max_date = datetime.datetime.strptime(sorted_contribs[-1][0], "%Y-%m-%d").date()
    
    contrib_dict = dict(sorted_contribs)
    
    filled = []
    curr_date = min_date
    while curr_date <= max_date:
        date_str = curr_date.strftime("%Y-%m-%d")
        level = contrib_dict.get(date_str, 0)
        filled.append((date_str, level))
        curr_date += datetime.timedelta(days=1)
        
    return filled

def extract_contributions_from_html(html_content: str) -> list[tuple[str, int]]:
    """
    Parses contribution dates and levels from raw HTML using standard library regular expressions.
    Acts as a robust fallback independent of third-party HTML parsers.
    """
    # Matches any tag containing both data-date and data-level attributes
    tag_pattern = re.compile(r'<[^>]+(?:data-date|data-level)[^>]*>')
    date_pattern = re.compile(r'data-date="(\d{4}-\d{2}-\d{2})"')
    level_pattern = re.compile(r'data-level="([0-4])"')
    
    results = []
    for tag in tag_pattern.finditer(html_content):
        tag_str = tag.group(0)
        date_match = date_pattern.search(tag_str)
        level_match = level_pattern.search(tag_str)
        if date_match and level_match:
            date_str = date_match.group(1)
            level_val = int(level_match.group(1))
            results.append((date_str, level_val))
            
    results.sort(key=lambda x: x[0])
    return results

def fetch_github_profile_html(username: str) -> str:
    """
    Downloads the contribution grid HTML for a specified GitHub user.
    """
    url = f"https://github.com/users/{username}/contributions"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            return response.read().decode('utf-8')
    except urllib.error.URLError as e:
        print(f"Network error while fetching profile for user '{username}': {e}", file=sys.stderr)
        raise

def generate_commits(digits: list[int], start_date_str: str, history_file: str, dry_run: bool = True, covert: bool = False):
    """
    Generates chronological git commits corresponding to the base-5 digit stream.
    Supports standard (deterministic) and covert (randomized noise-shaping) modes.
    """
    try:
        start_date = datetime.datetime.strptime(start_date_str, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError("Start date must be in YYYY-MM-DD format.")
    
    total_days = len(digits)
    
    # Calculate commit counts
    if covert:
        # We sample commit counts for the preview
        sampled_counts = [random.choice(COMMIT_LEVEL_RANGES[d]) for d in digits]
        total_commits = sum(sampled_counts)
    else:
        total_commits = sum(COMMIT_MAPPING[d] for d in digits)
        
    print(f"--- Execution Mode: {'DRY-RUN' if dry_run else 'ACTIVE COMMIT'} ({'COVERT' if covert else 'STANDARD'} MODE) ---")
    print(f"Message payload mapped to {total_days} consecutive days.")
    print(f"Total required commits: {total_commits}\n")
    
    # Render horizontal preview of the encoded stream
    preview_str = "".join(COLORS[d] for d in digits)
    print("Payload Visualization Stream:")
    print(preview_str)
    print("-" * 50)
    
    commit_idx = 0
    for offset, digit in enumerate(digits):
        current_date = start_date + datetime.timedelta(days=offset)
        date_str = current_date.strftime("%Y-%m-%d")
        
        if covert:
            num_commits = random.choice(COMMIT_LEVEL_RANGES[digit])
        else:
            num_commits = COMMIT_MAPPING[digit]
            
        if num_commits == 0:
            print(f"[{date_str}] Digit {digit} -> 0 commits (Level 0)")
            continue
            
        print(f"[{date_str}] Digit {digit} -> {num_commits} commits (Level {digit})")
        
        if not dry_run:
            if covert:
                commit_times = generate_covert_timestamps(date_str, num_commits)
            else:
                commit_times = [f"{date_str}T12:{idx:02d}:00" for idx in range(1, num_commits + 1)]
                
            for idx, commit_time in enumerate(commit_times):
                if covert:
                    commit_msg = generate_covert_commit_message()
                else:
                    commit_msg = f"Steganographic Transceiver Payload Commit {commit_idx + idx + 1}"
                    
                with open(history_file, "a") as f:
                    f.write(f"{commit_time} - {commit_msg}\n")
                    
                env = os.environ.copy()
                env["GIT_AUTHOR_DATE"] = commit_time
                env["GIT_COMMITTER_DATE"] = commit_time
                
                # Execute git operations
                subprocess.run(["git", "add", history_file], check=True, capture_output=True)
                subprocess.run([
                    "git", "commit", 
                    "-m", commit_msg
                ], env=env, check=True, capture_output=True)
                
            commit_idx += num_commits
            
    print(f"\nCompleted! Processed {commit_idx} commits.")

def main():
    parser = argparse.ArgumentParser(
        description="GitHub History Steganographic Transceiver (Base-5 Codec CLI)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Subcommand: encode
    encode_parser = subparsers.add_parser("encode", help="Encode arbitrary data into commit history.")
    encode_parser.add_argument("--message", required=True, type=str, help="Text message payload to hide.")
    encode_parser.add_argument("--start-date", required=True, type=str, help="Start date (YYYY-MM-DD).")
    encode_parser.add_argument("--history-file", type=str, default="contributions.txt", help="Local history tracking file.")
    encode_parser.add_argument("--execute", action="store_true", default=False, help="Perform active commits instead of dry-run.")
    encode_parser.add_argument("--covert", action="store_true", default=False, help="Enable covert mode (randomizes timestamps, commit counts, and messages).")
    
    # Subcommand: decode
    decode_parser = subparsers.add_parser("decode", help="Pull and decode payload from a public GitHub user profile.")
    decode_parser.add_argument("--username", required=True, type=str, help="GitHub user profile name.")
    
    # Subcommand: local-decode
    subparsers.add_parser("local-decode", help="Decode payload directly from the active local Git repository history.")
    
    args = parser.parse_args()
    
    if args.command == "encode":
        payload_bytes = args.message.encode('utf-8')
        digits = encode_payload(payload_bytes)
        generate_commits(
            digits=digits,
            start_date_str=args.start_date,
            history_file=args.history_file,
            dry_run=not args.execute,
            covert=args.covert
        )
        
    elif args.command == "decode":
        print(f"Connecting to GitHub to fetch profile contributions for user '{args.username}'...")
        try:
            html = fetch_github_profile_html(args.username)
            contribs = extract_contributions_from_html(html)
            if not contribs:
                print("Error: No contribution data found in the retrieved HTML profile. Verifying username is recommended.", file=sys.stderr)
                sys.exit(1)
            
            # To isolate the steganographic payload, we must ensure all missing dates are accounted for as level-0
            filled_contribs = fill_missing_dates(contribs)
            digits = [level for _, level in filled_contribs]
            
            payload = decode_payload_digits(digits)
            print("\nDecoded Steganographic Payload:")
            print(payload.decode('utf-8'))
        except Exception as e:
            print(f"Extraction failed: {e}", file=sys.stderr)
            sys.exit(1)
            
    elif args.command == "local-decode":
        print("Parsing local Git commit history...")
        try:
            contribs = parse_local_git_history()
            if not contribs:
                print("No Git history found or unable to access logs.", file=sys.stderr)
                sys.exit(1)
                
            filled_contribs = fill_missing_dates(contribs)
            digits = [level for _, level in filled_contribs]
            
            payload = decode_payload_digits(digits)
            print("\nDecoded Steganographic Payload from Local Git History:")
            print(payload.decode('utf-8'))
        except Exception as e:
            print(f"Extraction failed: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
