#!/bin/sh
export PYTHONDONTWRITEBYTECODE=1
exec python3 "${srcdir:-.}/TEST/test_sample_test_manager.py"
