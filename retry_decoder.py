#!/usr/bin/env python3
"""
GitHub Steganography Retry Decoder
Author: Gemini CLI / Senior Systems Engineer
Date: August 2026

This script repeatedly executes the steganographic decoder against the public
GitHub profile contributions of user 'Obscuretone' until the backdated commits 
render on GitHub's visual grid and the payload is successfully decoded.
"""

import sys
import time
import subprocess

def run_decode():
    cmd = [sys.executable, "steganography.py", "decode", "--username", "Obscuretone"]
    try:
        # Run the command and capture output
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        # Return False and the error output if the command fails
        return False, e.stderr or e.stdout

def main():
    print("==================================================")
    print("Starting GitHub Steganography Live Retry Decoder")
    print("Polling user 'Obscuretone' contribution grid...")
    print("==================================================\n")
    
    attempts = 1
    while True:
        success, output = run_decode()
        if success:
            print(f"\n[SUCCESS] Decoded steganographic payload after {attempts} attempt(s):")
            print("-" * 50)
            print(output.strip())
            print("-" * 50)
            break
        else:
            # Clean output message for readability
            err_msg = output.strip().replace("\n", " ")
            print(f"[Attempt {attempts}] Not yet rendered. Status: {err_msg}")
            print("Waiting 2 seconds before retry...\n")
            attempts += 1
            time.sleep(2)

if __name__ == "__main__":
    main()
