import argparse
import sys


def parse_cli_args():
    parser = argparse.ArgumentParser(description='CryptoCore - File encryption tool')

    parser.add_argument('--algorithm', required=True, choices=['aes'])
    parser.add_argument('--mode', required=True, choices=['ecb'])
    parser.add_argument('--encrypt', action='store_true')
    parser.add_argument('--decrypt', action='store_true')
    parser.add_argument('--key', required=True)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output')

    return parser.parse_args()