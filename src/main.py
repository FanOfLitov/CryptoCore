#!/usr/bin/env python3

import os
import sys

from .cli_parser import parse_cli_args
from .file_io import read_file_binary, write_file_binary
from .csprng import generate_key
from .modes.ecb import ecb_encrypt, ecb_decrypt
from .modes.cbc import cbc_encrypt, cbc_decrypt
from .modes.cfb import cfb_encrypt, cfb_decrypt
from .modes.ofb import ofb_encrypt, ofb_decrypt
from .modes.ctr import ctr_encrypt, ctr_decrypt

from .aead.etm import etm_encrypt



from .hash.sha256 import sha256_file
from .hash.sha3_256 import sha3_256_file


def extract_iv(ciphertext: bytes) -> tuple[bytes, bytes]:
    """Extract IV (first 16 bytes). Ensures file is long enough."""
    if len(ciphertext) < 16:
        raise ValueError("Input file too short to contain IV (need ≥ 16 bytes)")
    return ciphertext[:16], ciphertext[16:]


def handle_decryption(args, input_data):
    """Handle decryption operation"""

    from .aead.etm import etm_decrypt

    if not args.key:
        raise ValueError("Key is required for decryption")

    # Map mode -> decrypt function
    crypto_decrypt = {
        'ecb': ecb_decrypt,
        'cbc': cbc_decrypt,
        'cfb': cfb_decrypt,
        'ofb': ofb_decrypt,
        'ctr': ctr_decrypt,
    }

    decrypt_func = crypto_decrypt.get(args.mode)
    if not decrypt_func:
        raise ValueError(f"Unsupported mode {args.mode}")

    # AEAD mode (Verify-then-Decrypt)
    if getattr(args, 'aead', False):
        master_key = bytes.fromhex(args.key)
        pt = etm_decrypt(decrypt_func, master_key, input_data)
        return pt, None

    # Non-AEAD mode (legacy)
    key_bytes = bytes.fromhex(args.key)
    pt = decrypt_func(key_bytes, input_data)
    return pt, None


def handle_hash(args):
    """Handle hash and HMAC computation"""

    from .mac.hmac import HMAC
    from .file_io import read_file_binary
    from .hash.sha256 import sha256_file
    from .hash.sha3_256 import sha3_256_file

    # Read input file as bytes (IMPORTANT for HMAC)
    file_bytes = read_file_binary(args.input)

    # -------------------------
    # HMAC MODE
    # -------------------------
    if args.hmac:
        key = bytes.fromhex(args.key)
        hmac = HMAC(key)
        result = hmac.hexdigest(file_bytes)

        output_line = f"{result} {args.input}\n"

        # VERIFY MODE
        if args.verify:
            with open(args.verify, 'rb') as f:
                data = f.read()

            # Extract hex characters only, in order
            hex_chars = []
            for b in data:
                c = chr(b)
                if c in '0123456789abcdefABCDEF':
                    hex_chars.append(c)
                    if len(hex_chars) == 64:
                        break

            expected = ''.join(hex_chars)

            if len(expected) != 64:
                print("Error: Invalid HMAC file format", file=sys.stderr)
                sys.exit(1)

            if result.lower() == expected.lower():
                print("[OK] HMAC verification successful")
                sys.exit(0)
            else:
                print("[ERROR] HMAC verification failed", file=sys.stderr)
                sys.exit(1)

        # NORMAL OUTPUT
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_line)
        else:
            print(output_line, end='')

        return result

    # -------------------------
    # NORMAL HASH MODE
    # -------------------------
    hash_functions = {
        'sha256': sha256_file,
        'sha3-256': sha3_256_file,
    }

    hash_func = hash_functions.get(args.algorithm)
    if not hash_func:
        print(f"Error: Unsupported hash algorithm {args.algorithm}", file=sys.stderr)
        sys.exit(1)

    hash_value = hash_func(args.input)
    output_line = f"{hash_value} {args.input}\n"

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_line)
    else:
        print(output_line, end='')

    return hash_value


def handle_encryption(args, input_data):
    """Handle encryption operation"""

    from .aead.etm import etm_encrypt
    from .csprng import generate_random_bytes, generate_key

    # Map mode -> encrypt function
    crypto_encrypt = {
        'ecb': ecb_encrypt,
        'cbc': cbc_encrypt,
        'cfb': cfb_encrypt,
        'ofb': ofb_encrypt,
        'ctr': ctr_encrypt,
    }

    encrypt_func = crypto_encrypt.get(args.mode)
    if not encrypt_func:
        raise ValueError(f"Unsupported mode {args.mode}")

    # AEAD mode (Encrypt-then-MAC)
    if getattr(args, 'aead', False):
        if args.key:
            master_key = bytes.fromhex(args.key)
        else:
            # Generate 32-byte master key for AEAD
            master_key = generate_random_bytes(32)
            print(f"[INFO] Generated AEAD master key: {master_key.hex()}")

        out = etm_encrypt(encrypt_func, master_key, input_data)
        return out, None

    # Non-AEAD mode (legacy)
    if args.key:
        key_bytes = bytes.fromhex(args.key)
    else:
        key_bytes = generate_key()
        print(f"[INFO] Generated random key: {key_bytes.hex()}")

    out = encrypt_func(key_bytes, input_data)
    return out, None



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