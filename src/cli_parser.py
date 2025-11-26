import argparse
import sys
import os


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description='CryptoCore - File encryption tool using AES-128',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Encryption
  cryptocore --algorithm aes --mode ecb --encrypt --key 00112233445566778899aabbccddeeff --input file.txt --output file.enc

  # Decryption
  cryptocore --algorithm aes --mode ecb --decrypt --key 00112233445566778899aabbccddeeff --input file.enc --output file.dec
        '''
    )

    parser.add_argument('--algorithm',
                        required=True,
                        choices=['aes'],
                        help='Encryption algorithm (only aes supported)')

    parser.add_argument('--mode',
                        required=True,
                        choices=['ecb'],
                        help='Mode of operation (only ecb supported)')

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

    args = parser.parse_args()

    # Validate key format and length
    if not validate_key(args.key):
        print(f"Error: Key must be a 32-character hexadecimal string (16 bytes)", file=sys.stderr)
        print(f"Provided key: {args.key}", file=sys.stderr)
        sys.exit(1)

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


def derive_output_filename(input_path, is_encrypt):
    """Derive default output filename based on input and operation"""
    if is_encrypt:
        return input_path + '.enc'
    else:
        if input_path.endswith('.enc'):
            return input_path[:-4] + '.dec'
        else:
            return input_path + '.dec'