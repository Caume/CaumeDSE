#!/usr/bin/env python3
import sys


def main():
    if len(sys.argv) != 3:
        return 2

    output_path = sys.argv[2]
    with open(output_path, "w", newline="") as dst:
        dst.write("payload\n")
        dst.write("x" * (1024 * 1024 + 1))
        dst.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
