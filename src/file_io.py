import sys


def read_file_binary(filename):
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{filename}' not found", file=sys.stderr)
        sys.exit(1)

def write_file_binary(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)