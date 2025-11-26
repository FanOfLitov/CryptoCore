#!/usr/bin/env python3

import sys
import os

# Add src directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cli_parser import parse_cli_args
from file_io import read_file_binary, write_file_binary
from modes.ecb import ecb_encrypt, ecb_decrypt


def main():
    """
    Main entry point for CryptoCore
    """
    try:
        # Parse command line arguments
        args = parse_cli_args()

        # Read input file
        input_data = read_file_binary(args.input)

        # Convert key from hex string to bytes
        key_bytes = bytes.fromhex(args.key)

        # Perform encryption or decryption
        if args.encrypt:
            if args.algorithm == 'aes' and args.mode == 'ecb':
                output_data = ecb_encrypt(key_bytes, input_data)
            else:
                print(f"Error: Unsupported algorithm/mode combination: {args.algorithm}/{args.mode}",
                      file=sys.stderr)
                sys.exit(1)
        else:  # decrypt
            if args.algorithm == 'aes' and args.mode == 'ecb':
                try:
                    output_data = ecb_decrypt(key_bytes, input_data)
                except ValueError as e:
                    print(f"Decryption error: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                print(f"Error: Unsupported algorithm/mode combination: {args.algorithm}/{args.mode}",
                      file=sys.stderr)
                sys.exit(1)

        # Write output file
        write_file_binary(args.output, output_data)

        print(f"Success: {'Encrypted' if args.encrypt else 'Decrypted'} {args.input} -> {args.output}")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()