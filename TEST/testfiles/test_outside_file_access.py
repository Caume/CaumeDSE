#!/usr/bin/env python3
"""Negative parser fixture: requires read access to a host file outside parser temp."""
import csv
import sys


def main():
    if len(sys.argv) != 3:
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    try:
        with open("/etc/passwd", "rb") as host_file:
            host_file.read(1)
    except OSError:
        return 9

    with open(input_path, newline="") as src:
        rows = list(csv.reader(src))
    with open(output_path, "w", newline="") as dst:
        csv.writer(dst).writerows(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
