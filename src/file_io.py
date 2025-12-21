import sys


def read_file_binary(filename):

    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{filename}' not found", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied reading '{filename}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
        sys.exit(1)


def write_file_binary(filename, data):
    try:
        with open(filename, 'wb') as f:
            f.write(data)
    except PermissionError:
        print(f"Error: Permission denied writing to '{filename}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error writing file '{filename}': {e}", file=sys.stderr)
        sys.exit(1)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]