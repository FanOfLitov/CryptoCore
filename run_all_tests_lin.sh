#!/bin/bash
set -e

export PYTHONPATH=$(pwd)

echo "BASIC TESTS"
python3 -m tests.test_basik
python3 -m tests.test_modes

echo "HASH / HMAC"
python3 -m tests.test_hash
python3 -m tests.test_hmac

echo "AEAD"
python3 -m tests.test_aead

echo "KDF"
python3 -m tests.test_pbkdf2
python3 -m tests.test_hkdf

echo "ALL TESTS PASSED"
