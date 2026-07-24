#!/usr/bin/env python3
"""Negative parser fixture: requires access to the live HTTP verifier port."""
import csv
import socket
import sys


def main():
    if len(sys.argv) != 3:
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    try:
        with socket.create_connection(("127.0.0.1", 18080), timeout=2):
            pass
    except OSError:
        return 9

    with open(input_path, newline="") as src:
        rows = list(csv.reader(src))
    with open(output_path, "w", newline="") as dst:
        csv.writer(dst).writerows(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
