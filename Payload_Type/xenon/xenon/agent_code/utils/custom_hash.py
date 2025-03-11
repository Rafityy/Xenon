HASH_SEED = 0x811C9DC5
HASH_PRIME = 0x01000193

def custom_hash(data: str) -> int:
    hash_val = HASH_SEED
    for char in data:
        hash_val ^= ord(char)
        hash_val *= HASH_PRIME
        hash_val &= 0xFFFFFFFF  # Ensure it's a 32-bit unsigned integer
    return hash_val

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <string_to_hash>")
        sys.exit(1)

    hashed_value = custom_hash(sys.argv[1])
    print(f"0x{hashed_value:X}")
