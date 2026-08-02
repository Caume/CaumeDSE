#!/usr/bin/env python3
import csv
import sys


with open(sys.argv[1], newline="", encoding="utf-8") as source:
    reader = csv.DictReader(source)
    writer = csv.DictWriter(sys.stdout, fieldnames=["name", "salary"])
    writer.writeheader()
    for row in reader:
        writer.writerow({"name": row.get("name", ""), "salary": row.get("salary", "")})
