#!/usr/bin/env python3
"""Reviewed parser fixture: no network, shell, environment, or extra file reads."""
import csv
import sys


def main():
    if len(sys.argv) != 3:
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    with open(input_path, newline="") as src:
        rows = list(csv.reader(src))

    if not rows:
        with open(output_path, "w", newline="") as dst:
            pass
        return 0

    header = rows[0]
    try:
        salary_idx = header.index("salary")
    except ValueError:
        salary_idx = -1

    total = 0
    if salary_idx >= 0:
        for row in rows[1:]:
            if salary_idx < len(row):
                total += int(row[salary_idx])
                row[salary_idx] = str(total)

    with open(output_path, "w", newline="") as dst:
        writer = csv.writer(dst)
        writer.writerows(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
