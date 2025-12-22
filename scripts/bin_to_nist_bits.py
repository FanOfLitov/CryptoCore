import sys

def bin_to_nist_bits(bin_path: str, out_path: str):
    with open(bin_path, "rb") as f:
        data = f.read()

    with open(out_path, "w") as out:
        for b in data:
            out.write(f"{b:08b}")

    print(f"[OK] Converted {len(data)} bytes → {len(data) * 8} bits")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python bin_to_nist_bits.py <input.bin> <output.txt>")
        sys.exit(1)

    bin_to_nist_bits(sys.argv[1], sys.argv[2])
