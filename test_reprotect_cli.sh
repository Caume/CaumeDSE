#!/bin/sh
exec python3 "${srcdir:-.}/TEST/test_reprotect_cli.py" --admin ./caumedse-admin --fixture ./reprotect-fixture
