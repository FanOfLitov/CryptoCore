import argparse
import sys
import os
from csprng import generate_key


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description='CryptoCore - File encryption tool using AES-128',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Encryption with automatic key generation
  cryptocore --algorithm aes --mode cbc --encrypt --input file.txt --output file.enc

  # Encryption with provided key
  cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input file.txt --output file.enc

  # Decryption (key must be provided)
  cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --input file.enc --output file.dec
        '''
    )

    parser.add_argument('--algorithm',
                        required=True,
                        choices=['aes'],
                        help='Encryption algorithm (only aes supported)')

    parser.add_argument('--mode',
                        required=True,
                        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                        help='Mode of operation')

    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument('--encrypt',
                                 action='store_true',
                                 help='Perform encryption')
    operation_group.add_argument('--decrypt',
                                 action='store_true',
                                 help='Perform decryption')

    parser.add_argument('--key',
                        help='Encryption key as 32-character hexadecimal string (16 bytes). Optional for encryption')

    parser.add_argument('--input',
                        required=True,
                        help='Input file path')

    parser.add_argument('--output',
                        help='Output file path (default: derived from input)')

    parser.add_argument('--iv',
                        help='Initialization Vector as 32-character hexadecimal string (16 bytes). Required for decryption in CBC/CFB/OFB/CTR modes')

    args = parser.parse_args()

    # Validate key if provided
    if args.key:
        if not validate_key(args.key):
            print(f"Error: Key must be a 32-character hexadecimal string (16 bytes)", file=sys.stderr)
            print(f"Provided key: {args.key}", file=sys.stderr)
            sys.exit(1)

        # Check for weak keys
        if is_weak_key(args.key):
            print(f"Warning: The provided key appears to be weak. Consider using a randomly generated key.",
                  file=sys.stderr)

    # Key is required for decryption
    if args.decrypt and not args.key:
        print(f"Error: Key is required for decryption operations", file=sys.stderr)
        sys.exit(1)

    # Validate IV if provided
    if args.iv and not validate_key(args.iv):
        print(f"Error: IV must be a 32-character hexadecimal string (16 bytes)", file=sys.stderr)
        print(f"Provided IV: {args.iv}", file=sys.stderr)
        sys.exit(1)

    # Validate IV usage rules
    if args.encrypt and args.iv:
        print("Warning: IV is auto-generated during encryption. Provided IV will be ignored.", file=sys.stderr)
        args.iv = None

    # Validate input file exists
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' does not exist", file=sys.stderr)
        sys.exit(1)

    # Set default output filename if not provided
    if not args.output:
        args.output = derive_output_filename(args.input, args.encrypt)

    return args


def validate_key(key_str):
    """Validate that key is a 32-character hex string (16 bytes)"""
    if len(key_str) != 32:
        return False
    try:
        bytes.fromhex(key_str)
        return True
    except ValueError:
        return False


def is_weak_key(key_str):
    """Check if key is weak (all zeros, sequential bytes, etc.)"""
    key_bytes = bytes.fromhex(key_str)

    # Check for all zeros
    if all(b == 0 for b in key_bytes):
        return True

    # Check for sequential bytes
    is_sequential_inc = all(key_bytes[i] == key_bytes[i - 1] + 1 for i in range(1, len(key_bytes)))
    is_sequential_dec = all(key_bytes[i] == key_bytes[i - 1] - 1 for i in range(1, len(key_bytes)))

    if is_sequential_inc or is_sequential_dec:
        return True

    # Check for repeated patterns
    if key_bytes == key_bytes[:8] * 2:  # Repeated 8-byte pattern
        return True

    return False


def derive_output_filename(input_path, is_encrypt):
    """Derive default output filename based on input and operation"""
    if is_encrypt:
        return input_path + '.enc'
    else:
        if input_path.endswith('.enc'):
            return input_path[:-4] + '.dec'
        else:
            return input_path + '.dec'


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description='CryptoCore - File encryption tool using AES-128',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Encryption (IV auto-generated)
  cryptocore --algorithm aes --mode cbc --encrypt --key 00112233445566778899aabbccddeeff --input file.txt --output file.enc

  # Decryption (IV provided)
  cryptocore --algorithm aes --mode cbc --decrypt --key 00112233445566778899aabbccddeeff --iv aabbccddeeff00112233445566778899 --input file.enc --output file.dec
        '''
    )

    parser.add_argument('--algorithm',
                        required=True,
                        choices=['aes'],
                        help='Encryption algorithm (only aes supported)')

    parser.add_argument('--mode',
                        required=True,
                        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],  # ← ДОБАВЛЕНЫ НОВЫЕ РЕЖИМЫ
                        help='Mode of operation')

    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument('--encrypt',
                                 action='store_true',
                                 help='Perform encryption')
    operation_group.add_argument('--decrypt',
                                 action='store_true',
                                 help='Perform decryption')

    parser.add_argument('--key',
                        required=True,
                        help='Encryption key as 32-character hexadecimal string (16 bytes)')

    parser.add_argument('--input',
                        required=True,
                        help='Input file path')

    parser.add_argument('--output',
                        help='Output file path (default: derived from input)')

    parser.add_argument('--iv',  # ← НОВЫЙ АРГУМЕНТ
                        help='Initialization Vector as 32-character hexadecimal string (16 bytes). Required for decryption in CBC/CFB/OFB/CTR modes')

    args = parser.parse_args()

    # Validate key format and length
    if not validate_key(args.key):
        print(f"Error: Key must be a 32-character hexadecimal string (16 bytes)", file=sys.stderr)
        print(f"Provided key: {args.key}", file=sys.stderr)
        sys.exit(1)

    # Validate IV if provided
    if args.iv and not validate_key(args.iv):
        print(f"Error: IV must be a 32-character hexadecimal string (16 bytes)", file=sys.stderr)
        print(f"Provided IV: {args.iv}", file=sys.stderr)
        sys.exit(1)

    # Validate IV usage rules
    if args.encrypt and args.iv:
        print("Warning: IV is auto-generated during encryption. Provided IV will be ignored.", file=sys.stderr)
        args.iv = None  # Ignore IV for encryption

    if args.decrypt and args.mode != 'ecb' and not args.iv:
        # Check if we can read IV from file (will be handled later)
        pass  # This will be handled in file I/O

    # Validate input file exists
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' does not exist", file=sys.stderr)
        sys.exit(1)

    # Set default output filename if not provided
    if not args.output:
        args.output = derive_output_filename(args.input, args.encrypt)

    return args