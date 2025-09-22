# Design a Python-based experiment to analyze the performance of MD5, SHA-1, and
# SHA-256 hashing techniques in terms of computation time and collision resistance.
# Generate a dataset of random strings ranging from 50 to 100 strings, compute the hash
# values using each hashing technique, and measure the time taken for hash computation.
# Implement collision detection algorithms to identify any collisions within the hashed dataset


import hashlib
import random
import string
import time


def generate_random_strings(n=75, min_len=10, max_len=50):
    strings = []
    for _ in range(n):
        length = random.randint(min_len, max_len)
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        strings.append(rand_str)
    return strings


def compute_hashes(strings, algorithm='md5'):
    hash_func = getattr(hashlib, algorithm)
    hashes = []
    start_time = time.perf_counter()
    for s in strings:
        h = hash_func(s.encode('utf-8')).hexdigest()
        hashes.append(h)
    elapsed = time.perf_counter() - start_time
    return hashes, elapsed


def detect_collisions(hashes):
    seen = set()
    collisions = []
    for i, h in enumerate(hashes):
        if h in seen:
            collisions.append(h)
        else:
            seen.add(h)
    return collisions


def run_experiment():
    # Generate dataset
    n_strings = random.randint(50, 100)
    print(f"Generating {n_strings} random strings...")
    strings = generate_random_strings(n=n_strings)

    algorithms = ['md5', 'sha1', 'sha256']
    results = {}

    for algo in algorithms:
        print(f"\nComputing hashes with {algo.upper()}...")
        hashes, elapsed = compute_hashes(strings, algorithm=algo)
        collisions = detect_collisions(hashes)
        results[algo] = {
            'time': elapsed,
            'collisions': collisions,
            'collision_count': len(collisions)
        }

        print(f"Time taken: {elapsed:.6f} seconds")
        print(f"Collisions detected: {len(collisions)}")
        if collisions:
            print("Collision hashes:")
            for c in collisions:
                print(c)

    print("\nSummary:")
    for algo in algorithms:
        print(f"{algo.upper()}: Time = {results[algo]['time']:.6f}s, Collisions = {results[algo]['collision_count']}")


if __name__ == "__main__":
    run_experiment()
