#!/usr/bin/env python3

import sys
import os

# Add src directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cli_parser import parse_cli_args
from file_io import read_file_binary, write_file_binary
from csprng import generate_key
from modes.ecb import ecb_encrypt, ecb_decrypt
from modes.cbc import cbc_encrypt, cbc_decrypt
from modes.cfb import cfb_encrypt, cfb_decrypt
from modes.ofb import ofb_encrypt, ofb_decrypt
from modes.ctr import ctr_encrypt, ctr_decrypt


def get_crypto_functions(mode, operation):
    """Return appropriate encryption/decryption functions based on mode"""
    crypto_functions = {
        'ecb': (ecb_encrypt, ecb_decrypt),
        'cbc': (cbc_encrypt, cbc_decrypt),
        'cfb': (cfb_encrypt, cfb_decrypt),
        'ofb': (ofb_encrypt, ofb_decrypt),
        'ctr': (ctr_encrypt, ctr_decrypt),
    }

    return crypto_functions.get(mode, (None, None))


def handle_encryption(args, input_data):
    """Handle encryption operation"""
    # Generate or use provided key
    if args.key:
        key_bytes = bytes.fromhex(args.key)
        generated_key = None
    else:
        generated_key = generate_key()
        key_bytes = generated_key
        # Print generated key to stdout
        key_hex = generated_key.hex()
        print(f"[INFO] Generated random key: {key_hex}")

    encrypt_func, _ = get_crypto_functions(args.mode, 'encrypt')

    if not encrypt_func:
        print(f"Error: Unsupported mode {args.mode}", file=sys.stderr)
        sys.exit(1)

    output_data = encrypt_func(key_bytes, input_data)
    return output_data, generated_key


def handle_decryption(args, input_data):
    """Handle decryption operation"""
    # Key is required for decryption
    key_bytes = bytes.fromhex(args.key)

    _, decrypt_func = get_crypto_functions(args.mode, 'decrypt')

    if not decrypt_func:
        print(f"Error: Unsupported mode {args.mode}", file=sys.stderr)
        sys.exit(1)

    # Handle IV for different modes
    if args.mode == 'ecb':
        # ECB doesn't use IV
        return decrypt_func(key_bytes, input_data), None
    else:
        # For other modes, handle IV
        if args.iv:
            # IV provided via CLI
            iv_bytes = bytes.fromhex(args.iv)
            ciphertext_with_iv = iv_bytes + input_data
        else:
            # IV should be in the file
            if len(input_data) < 16:
                print(f"Error: Input file too short to contain IV (minimum 16 bytes required)", file=sys.stderr)
                sys.exit(1)
            ciphertext_with_iv = input_data

        return decrypt_func(key_bytes, ciphertext_with_iv), None


def main():
    """
    Main entry point for CryptoCore
    """
    try:
        # Parse command line arguments
        args = parse_cli_args()

        # Read input file
        input_data = read_file_binary(args.input)

        # Perform encryption or decryption
        if args.encrypt:
            output_data, generated_key = handle_encryption(args, input_data)
        else:  # decrypt
            try:
                output_data, _ = handle_decryption(args, input_data)
            except ValueError as e:
                print(f"Decryption error: {e}", file=sys.stderr)
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