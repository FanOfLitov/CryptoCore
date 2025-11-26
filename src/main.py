#!/usr/bin/env python3

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cli_parser import parse_cli_args
from file_io import read_file_binary, write_file_binary
from csprng import generate_key
from modes.ecb import ecb_encrypt, ecb_decrypt
from modes.cbc import cbc_encrypt, cbc_decrypt
from modes.cfb import cfb_encrypt, cfb_decrypt
from modes.ofb import ofb_encrypt, ofb_decrypt
from modes.ctr import ctr_encrypt, ctr_decrypt
from hash.sha256 import sha256_file
from hash.sha3_256 import sha3_256_file


def handle_encryption(args, input_data):
    """Handle encryption operation"""
    if args.key:
        key_bytes = bytes.fromhex(args.key)
        generated_key = None
    else:
        generated_key = generate_key()
        key_bytes = generated_key
        print(f"[INFO] Generated random key: {generated_key.hex()}")

    crypto_functions = {
        'ecb': (ecb_encrypt, ecb_decrypt),
        'cbc': (cbc_encrypt, cbc_decrypt),
        'cfb': (cfb_encrypt, cfb_decrypt),
        'ofb': (ofb_encrypt, ofb_decrypt),
        'ctr': (ctr_encrypt, ctr_decrypt),
    }

    encrypt_func, _ = crypto_functions.get(args.mode, (None, None))

    if not encrypt_func:
        print(f"Error: Unsupported mode {args.mode}", file=sys.stderr)
        sys.exit(1)

    output_data = encrypt_func(key_bytes, input_data)
    return output_data, generated_key


def handle_decryption(args, input_data):
    """Handle decryption operation"""
    key_bytes = bytes.fromhex(args.key)

    crypto_functions = {
        'ecb': (ecb_encrypt, ecb_decrypt),
        'cbc': (cbc_encrypt, cbc_decrypt),
        'cfb': (cfb_encrypt, cfb_decrypt),
        'ofb': (ofb_encrypt, ofb_decrypt),
        'ctr': (ctr_encrypt, ctr_decrypt),
    }

    _, decrypt_func = crypto_functions.get(args.mode, (None, None))

    if not decrypt_func:
        print(f"Error: Unsupported mode {args.mode}", file=sys.stderr)
        sys.exit(1)

    if args.mode == 'ecb':
        return decrypt_func(key_bytes, input_data), None
    else:
        if args.iv:
            iv_bytes = bytes.fromhex(args.iv)
            ciphertext_with_iv = iv_bytes + input_data
        else:
            if len(input_data) < 16:
                print(f"Error: Input file too short to contain IV", file=sys.stderr)
                sys.exit(1)
            ciphertext_with_iv = input_data

        return decrypt_func(key_bytes, ciphertext_with_iv), None


def handle_hash(args):
    """Handle hash computation"""
    hash_functions = {
        'sha256': sha256_file,
        'sha3-256': sha3_256_file,
    }

    hash_func = hash_functions.get(args.algorithm)
    if not hash_func:
        print(f"Error: Unsupported hash algorithm {args.algorithm}", file=sys.stderr)
        sys.exit(1)

    # Compute hash
    hash_value = hash_func(args.input)

    # Format: HASH_VALUE INPUT_FILE_PATH
    output_line = f"{hash_value} {args.input}\n"

    # Output to file or stdout
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_line)
        print(f"Hash written to: {args.output}")
    else:
        print(output_line, end='')

    return hash_value


def main():
    """Main entry point"""
    try:
        args = parse_cli_args()

        if args.command == 'dgst':
            handle_hash(args)
        else:  # encryption/decryption
            input_data = read_file_binary(args.input)

            if args.encrypt:
                output_data, _ = handle_encryption(args, input_data)
            else:
                output_data, _ = handle_decryption(args, input_data)

            write_file_binary(args.output, output_data)
            operation = 'Encrypted' if args.encrypt else 'Decrypted'
            print(f"Success: {operation} {args.input} -> {args.output}")

    except KeyboardInterrupt:
        print("\nOperation cancelled", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()