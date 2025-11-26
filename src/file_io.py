import sys


def read_file_binary(filename):
    """
    Read entire file content as binary

    Args:
        filename: Path to file

    Returns:
        bytes: File content

    Exits with error code 1 if file cannot be read
    """
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
    """
    Write binary data to file

    Args:
        filename: Path to output file
        data: Binary data to write
    """
    try:
        with open(filename, 'wb') as f:
            f.write(data)
    except PermissionError:
        print(f"Error: Permission denied writing to '{filename}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error writing file '{filename}': {e}", file=sys.stderr)
        sys.exit(1)