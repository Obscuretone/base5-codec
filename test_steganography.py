#!/usr/bin/env python3
"""
Unit Tests for GitHub History Steganographic Transceiver (Base-5 Codec)
Author: Gemini CLI / Senior Systems Engineer
Date: August 2026

This test suite verifies the correctness, mathematical integrity, and
robustness of the steganographic encoding/decoding process, HTML parsing logic,
and missing date reconstitution functionality.
"""

import unittest
import datetime
from steganography import (
    byte_to_base5,
    base5_to_byte,
    encode_payload,
    decode_payload_digits,
    fill_missing_dates,
    extract_contributions_from_html,
    COMMIT_LEVEL_RANGES,
    generate_covert_commit_message,
    generate_covert_timestamps,
    MAGIC_HEADER,
    MAGIC_FOOTER
)

class TestSteganographyCodec(unittest.TestCase):

    def test_byte_base5_conversions(self):
        """
        Verifies that converting bytes to base-5 digits and back is perfectly identity-preserving
        across the entire 8-bit space [0, 255].
        """
        for byte_val in range(256):
            digits = byte_to_base5(byte_val)
            self.assertEqual(len(digits), 4, "Each byte must yield exactly 4 base-5 digits.")
            for d in digits:
                self.assertTrue(0 <= d <= 4, f"Digit {d} must be within base-5 range [0, 4]")
            
            reconstructed_byte = base5_to_byte(digits)
            self.assertEqual(byte_val, reconstructed_byte, "Reconstructed byte must match the original value.")

    def test_invalid_conversions(self):
        """
        Verifies that out-of-bounds inputs to conversion functions correctly trigger ValueErrors.
        """
        with self.assertRaises(ValueError):
            byte_to_base5(-1)
        with self.assertRaises(ValueError):
            byte_to_base5(256)
        with self.assertRaises(ValueError):
            base5_to_byte([0, 1, 2]) # Length not 4
        with self.assertRaises(ValueError):
            base5_to_byte([0, 1, 2, 5]) # Digit 5 is invalid in base-5

    def test_steganographic_payload_isolation(self):
        """
        Verifies that the steganographic transceiver can successfully hide, isolate, and extract
        arbitrary byte payloads when prepended/appended with random contribution levels (noise).
        """
        payloads = [
            b"Hello, World!",
            b"",
            b"A secret key: 0x9F82A2E5B10D",
            bytes(range(256)) # Exhaustive test of all binary characters
        ]
        
        for payload in payloads:
            digits = encode_payload(payload)
            
            # Test direct decoding
            decoded = decode_payload_digits(digits)
            self.assertEqual(payload, decoded, f"Failed to decode payload: {payload}")
            
            # Test decoding with prepended and appended noise (simulating unrelated git commits)
            noise_prefix = [0, 1, 2, 3, 4, 0, 1, 2]
            noise_suffix = [4, 3, 2, 1, 0, 4, 3, 2]
            noisy_digits = noise_prefix + digits + noise_suffix
            
            decoded_noisy = decode_payload_digits(noisy_digits)
            self.assertEqual(payload, decoded_noisy, "Failed to isolate and decode payload from noisy channel.")

    def test_missing_header_footer_errors(self):
        """
        Verifies that decoding throws ValueErrors if the magic header or footer is corrupted or missing.
        """
        digits = encode_payload(b"Test message")
        
        # Corrupt the header (first block of 4 digits)
        corrupted_header = list(digits)
        corrupted_header[0] = (corrupted_header[0] + 1) % 5
        with self.assertRaises(ValueError):
            decode_payload_digits(corrupted_header)
            
        # Corrupt the footer (last block of 4 digits)
        corrupted_footer = list(digits)
        corrupted_footer[-1] = (corrupted_footer[-1] + 1) % 5
        with self.assertRaises(ValueError):
            decode_payload_digits(corrupted_footer)

    def test_fill_missing_dates(self):
        """
        Verifies that gaps in chronological contributions are correctly filled with level-0 values.
        """
        contributions = [
            ("2023-01-01", 3),
            ("2023-01-02", 4),
            ("2023-01-05", 2)
        ]
        
        expected_filled = [
            ("2023-01-01", 3),
            ("2023-01-02", 4),
            ("2023-01-03", 0), # Filled
            ("2023-01-04", 0), # Filled
            ("2023-01-05", 2)
        ]
        
        filled = fill_missing_dates(contributions)
        self.assertEqual(filled, expected_filled, "Reconstituted date sequence does not match expected output.")

    def test_extract_contributions_from_html(self):
        """
        Verifies that the HTML parser correctly extracts dates and levels from tags,
        independent of tag type (rect, td) and attribute ordering.
        """
        mock_html = """
        <div class="calendar">
            <rect class="ContributionCalendar-day" width="10" height="10" x="-14" y="0" data-date="2023-01-01" data-level="1" rx="2" ry="2"></rect>
            <td class="ContributionCalendar-day" data-level="4" data-date="2023-01-02"></td>
            <span>Random other tag without dates</span>
            <rect class="ContributionCalendar-day" data-date="2023-01-03" data-level="0"></rect>
        </div>
        """
        
        expected_contribs = [
            ("2023-01-01", 1),
            ("2023-01-02", 4),
            ("2023-01-03", 0)
        ]
        
        extracted = extract_contributions_from_html(mock_html)
        self.assertEqual(extracted, expected_contribs, "Parsed contribution levels or dates do not match expected outcomes.")

    def test_covert_commit_mapping_ranges(self):
        """
        Verifies that any selected commit count inside COMMIT_LEVEL_RANGES for a digit
        decodes back to the exact correct base-5 digit (level).
        """
        for digit, count_list in COMMIT_LEVEL_RANGES.items():
            for count in count_list:
                # Reconstruct level from count mapping logic (identical to parse_local_git_history)
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
                self.assertEqual(digit, level, f"Count {count} for digit {digit} incorrectly mapped to level {level}.")

    def test_generate_covert_commit_message(self):
        """
        Verifies that generate_covert_commit_message returns non-empty strings conforming
        to standard Git message formatting.
        """
        for _ in range(20):
            msg = generate_covert_commit_message()
            self.assertTrue(isinstance(msg, str), "Message must be a string.")
            self.assertTrue(len(msg) > 0, "Message must not be empty.")
            self.assertTrue(":" in msg, "Message must have a prefix separator colon.")

    def test_generate_covert_timestamps(self):
        """
        Verifies that generate_covert_timestamps returns chronologically sorted, valid
        ISO 8601-like business hour timestamps for a given date.
        """
        date_str = "2026-05-15"
        count = 5
        timestamps = generate_covert_timestamps(date_str, count)
        
        self.assertEqual(len(timestamps), count, "Timestamp count mismatch.")
        
        # Verify chronological order
        for idx in range(count - 1):
            self.assertTrue(timestamps[idx] <= timestamps[idx+1], "Timestamps are not chronologically sorted.")
            
        # Verify hour bounds
        for ts in timestamps:
            self.assertTrue(ts.startswith(date_str), "Timestamp date prefix mismatch.")
            time_part = ts.split("T")[1]
            hour = int(time_part.split(":")[0])
            self.assertTrue(9 <= hour <= 17, f"Hour {hour} is outside business hours [9, 17]")

if __name__ == "__main__":
    unittest.main()
