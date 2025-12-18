import argparse
import os
import sys


def parse_cli_args():

    parser = argparse.ArgumentParser(
        description='CryptoCore - File encryption and hashing tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
        
Examples:
  # Encryption with automatic key generation
  cryptocore --algorithm aes --mode cbc --encrypt --input file.txt --output file.enc

  # Hash computation
  cryptocore dgst --algorithm sha256 --input document.pdf
  cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Encryption/decryption command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encryption/decryption operations')
    encrypt_parser.add_argument('--algorithm', required=True, choices=['aes'])
    encrypt_parser.add_argument('--mode', required=True, choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'])

    operation_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument('--encrypt', action='store_true')
    operation_group.add_argument('--decrypt', action='store_true')

    encrypt_parser.add_argument('--key', help='Encryption key as 32-character hexadecimal string')
    encrypt_parser.add_argument('--input', required=True)
    encrypt_parser.add_argument('--output')
    encrypt_parser.add_argument('--iv', help='Initialization Vector as 32-character hexadecimal string')

    # Hash command
    hash_parser = subparsers.add_parser('dgst', help='Hash computation')
    hash_parser.add_argument('--algorithm', required=True, choices=['sha256', 'sha3-256'])
    hash_parser.add_argument('--input', required=True)
    hash_parser.add_argument('--output', help='Output file for hash (default: stdout)')

    #5 мелстоун
    hash_parser.add_argument('--hmac', action='store_true', help='Enable HMAC mode')
    hash_parser.add_argument('--key', help='HMAC key as hex string')
    hash_parser.add_argument('--verify', help='Verify HMAC from file')

    args = parser.parse_args()

    # Handle no command provided
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Validate encryption-specific arguments
    if args.command == 'dgst' and args.hmac:
        if not args.key:
            print("Error: --key is required when using --hmac", file=sys.stderr)
            sys.exit(1)
        try:
            bytes.fromhex(args.key)
        except ValueError:
            print("Error: HMAC key must be a hexadecimal string", file=sys.stderr)
            sys.exit(1)

    if args.command == 'encrypt':
        if args.key and not validate_key(args.key):
            print(f"Error: Key must be a 32-character hexadecimal string", file=sys.stderr)
            sys.exit(1)

        if args.key and is_weak_key(args.key):
            print(f"Warning: The provided key appears to be weak", file=sys.stderr)

        if args.decrypt and not args.key:
            print(f"Error: Key is required for decryption", file=sys.stderr)
            sys.exit(1)

        if args.iv and not validate_key(args.iv):
            print(f"Error: IV must be a 32-character hexadecimal string", file=sys.stderr)
            sys.exit(1)

        if args.encrypt and args.iv:
            print("Warning: IV is auto-generated during encryption", file=sys.stderr)
            args.iv = None

    # Validate input file exists
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' does not exist", file=sys.stderr)
        sys.exit(1)

    # Set default output filename for encryption
    if args.command == 'encrypt' and not args.output:
        args.output = derive_output_filename(args.input, getattr(args, 'encrypt', False))

    return args


def validate_key(key_str):
    """Validate that key is a 32-character hex string"""
    if len(key_str) != 32:
        return False
    try:
        bytes.fromhex(key_str)
        return True
    except ValueError:
        return False


def is_weak_key(key_str):
    """Check if key is weak"""
    key_bytes = bytes.fromhex(key_str)

    if all(b == 0 for b in key_bytes):
        return True

    is_sequential_inc = all(key_bytes[i] == key_bytes[i - 1] + 1 for i in range(1, len(key_bytes)))
    is_sequential_dec = all(key_bytes[i] == key_bytes[i - 1] - 1 for i in range(1, len(key_bytes)))

    return is_sequential_inc or is_sequential_dec


def derive_output_filename(input_path, is_encrypt):
    """Derive default output filename"""
    if is_encrypt:
        return input_path + '.enc'
    else:
        if input_path.endswith('.enc'):
            return input_path[:-4] + '.dec'
        else:
            return input_path + '.dec'

def validate_hex_len(hex_str, expected_len):
    if len(hex_str) != expected_len:
        return False
    try:
        bytes.fromhex(hex_str)
        return True
    except ValueError:
        return False