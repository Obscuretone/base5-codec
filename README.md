# base5-codec (GitHub History Steganographic Transceiver)

`base5-codec` is a steganographic tool that encodes, embeds, and retrieves arbitrary binary data within a GitHub commit history. The system maps raw byte streams into the five contribution levels (0 through 4) displayed on GitHub's profile calendar grid, using a base-5 representation.

---

## How It Works

### 1. Base-5 Mapping
GitHub's profile contribution grid renders exactly five discrete states. Each level is mapped to a range of commit frequencies:
*   **Level 0 (Gray):** 0 commits
*   **Level 1 (Light Green):** 1–2 commits
*   **Level 2 (Medium Green):** 3–5 commits
*   **Level 3 (Dark Green):** 6–9 commits
*   **Level 4 (Darkest Green):** 10+ commits

### 2. Block Encoding (4 Digits/Byte)
Raw 8-bit bytes ($0 \le B \le 255$) are decomposed into fixed-width blocks of exactly 4 base-5 digits:
$$B = d_3 \cdot 5^3 + d_2 \cdot 5^2 + d_1 \cdot 5^1 + d_0 \cdot 5^0$$
Using a fixed-width block size isolates corrupt or missing daily commit levels to a single byte ($O(1)$ blast radius), preventing global framing desynchronization.

### 3. Digit-Level Sliding Window Alignment
To recover payloads from complex Git histories containing unrelated commits (e.g. other years or baseline code additions), the decoder performs a digit-by-digit sliding-window scan for the magic sequences `STEG` and `END` encoded in base-5:
*   `STEG` signature: `[3, 1, 3, 0, 4, 1, 3, 0, 4, 3, 2, 0, 1, 4, 2, 0]`
*   `END` signature: `[4, 3, 2, 0, 3, 0, 3, 0, 3, 3, 2, 0]`

Once the decoder identifies the header boundary, it decodes the payload in perfect 4-digit blocks, rendering it immune to temporal alignment offsets or adjacent noise.

### 4. Covert Mode
Standard synthetic commit histories have uniform timestamps, static messages, and constant daily commit counts that are trivial to detect. Enabling `--covert` applies noise-shaping to mimic real developer behavior:
*   **Temporal Jitter:** Commits are randomized across natural business hours ($09:15:00$ to $17:45:00$) and sorted chronologically.
*   **Commit Count Jitter:** Daily commit counts are randomly sampled from the valid range of each target level (e.g., Level 2 will write a random choice of 3, 4, or 5 commits).
*   **Semantic Message Synthesis:** Commit messages are generated dynamically using conventional prefixes (`feat`, `fix`, `docs`, `refactor`, `test`) paired with realistic summaries (e.g. `refactor: resolve threading race condition in consumer stream`).

---

## Installation & Testing

No external dependencies are required. The script uses Python's standard library.

### Run Unit Tests
```bash
python3 -m unittest test_steganography.py
```

### Run End-to-End Local Integration Test
Executes a complete test loop (initialize repository, encode message, generate covert commits, parse Git log, and decode) in a temporary workspace:
```bash
# Create an isolated temporary test repository
mkdir -p /tmp/test-steg-repo
cd /tmp/test-steg-repo
git init
git config user.name "Steg Tester"
git config user.email "tester@steg.com"

# Encode and execute the steganographic commits starting on 2025-01-01
python3 /Users/evan.dentremont/Development/world-map-2023/steganography.py encode --message "A rigorous steganography integration test." --start-date "2025-01-01" --execute

# Parse local git history and decode
python3 /Users/evan.dentremont/Development/world-map-2023/steganography.py local-decode

# Clean up
cd /
rm -rf /tmp/test-steg-repo
```

---

## CLI Usage

### Encode & Generate Commits (Dry-Run)
Calculates and visualizes the commit mapping without executing commits:
```bash
python3 steganography.py encode --message "Once upon a midnight dreary..." --start-date "2025-01-01" --covert
```

### Encode & Generate Commits (Active)
Writes the steganographic commits directly to the active Git branch:
```bash
python3 steganography.py encode --message "Once upon a midnight dreary..." --start-date "2025-01-01" --covert --execute
```

### Decode from Local Git History
Parses local repository commit history directly:
```bash
python3 steganography.py local-decode
```

### Decode from Live GitHub Profile HTML
Fetches and decodes the steganographic message from a user's public contribution calendar:
```bash
python3 steganography.py decode --username Obscuretone
```

### Poll Public Profile until Rendered
Polling script to query the live GitHub page every 2 seconds until the contribution calendar cache updates:
```bash
python3 retry_decoder.py
```
