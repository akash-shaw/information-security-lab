import time

MASK32 = 0xFFFFFFFF

def hash_gen(s: str, h: int, mult: int):
    """Compute hash of the whole string, print it each loop iteration, repeat."""
    try:
        while True:
            cur = h & MASK32
            for ch in s:
                cur = (cur * mult + ord(ch)) & MASK32
            cur ^= (cur >> 16)
            cur = (cur * 0x85ebca6b) & MASK32
            cur ^= (cur >> 13)
            print(f"Hash: {cur:#010x}")
            h = cur
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopped.")

def main():
    hash_init = int(input("Enter initial Hash value: "))
    hash_mult = int(input("Enter Hash Multiplier: "))

    s = input("Enter String to Hash: ")
    print("Welcome to the Hash Generator™: ")
    hash_gen(s, hash_init, hash_mult)

if __name__ == '__main__':
    main()

