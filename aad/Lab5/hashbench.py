import hashlib
import random
import string
import time

def ds_gen(dsize):
    """Generate random strings dataset"""
    dataset = []
    for _ in range(dsize):
        length = random.randint(500000, 1000000)
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(random_string)
    return dataset

def hash_benchmark(dataset, hash_func):
    """Benchmark hashing function and detect collisions"""
    start_time = time.time()
    hashes = {}
    collisions = []
    
    for data in dataset:
        hash_value = hash_func(data.encode()).hexdigest()
        if hash_value in hashes:
            collisions.append((data, hashes[hash_value]))
        else:
            hashes[hash_value] = data
    
    end_time = time.time()
    return end_time - start_time, len(collisions), collisions

def main():
    dsize = int(input("Enter data size (50-100): "))
    dsize = max(50, min(100, dsize))  # Ensure range 50-100
    
    dataset = ds_gen(dsize)
    
    hash_functions = [
        (hashlib.md5, "MD5"),
        (hashlib.sha1, "SHA-1"), 
        (hashlib.sha256, "SHA-256")
    ]
    
    print(f"Testing with {len(dataset)} strings\n")
    
    for hash_func, name in hash_functions:
        time_taken, collision_count, collisions = hash_benchmark(dataset, hash_func)
        print(f"{name}:")
        print(f"  Time: {time_taken:.6f} seconds")
        print(f"  Collisions: {collision_count}")
        if collisions:
            print(f"  Collision pairs: {collisions[:3]}")  # Show first 3
        print()

if __name__ == '__main__':
    main()
