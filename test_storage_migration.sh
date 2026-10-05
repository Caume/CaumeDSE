#!/bin/sh
exec python3 "${srcdir:-.}/TEST/test_storage_migration.py" --admin ./caumedse-admin --fixture ./reprotect-fixture
