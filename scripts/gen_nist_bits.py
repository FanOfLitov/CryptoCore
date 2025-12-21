from src.csprng import generate_random_bytes


DATA_LEN = 100_000  # 100 KB = 800 000 бит

data = generate_random_bytes(DATA_LEN)

with open("nist_bits.txt", "w") as f:
    for b in data:
        f.write(f"{b:08b}")
