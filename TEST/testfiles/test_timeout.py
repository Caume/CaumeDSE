#!/usr/bin/env python3
import sys
import time


def main():
    if len(sys.argv) != 3:
        return 2
    time.sleep(15)
    return 0


if __name__ == "__main__":
    sys.exit(main())
