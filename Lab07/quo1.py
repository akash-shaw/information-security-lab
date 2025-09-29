import random
import math

# ----------------------------
# Utility Functions
# ----------------------------

def lcm(a, b):
    """Compute least common multiple of a and b."""
    return abs(a * b) // math.gcd(a, b)

def L(u, n):
    """L function used in decryption: L(u) = (u - 1) // n"""
    return (u - 1) // n

def modinv(a, m):
    """Modular inverse using Extended Euclidean Algorithm."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)

# ----------------------------
# Paillier Key Generation
# ----------------------------

def generate_keypair(bit_length=128):
    # Choose two large primes p and q
    p = get_prime(bit_length // 2)
    q = get_prime(bit_length // 2)
    while q == p:
        q = get_prime(bit_length // 2)

    n = p * q
    g = n + 1  # Common choice of g

    # λ = lcm(p-1, q-1)
    lam = lcm(p - 1, q - 1)

    # μ = (L(g^λ mod n^2))^(-1) mod n
    n_square = n * n
    u = pow(g, lam, n_square)
    l_val = L(u, n)
    mu = modinv(l_val, n)

    public_key = (n, g)
    private_key = (lam, mu)
    return public_key, private_key

def get_prime(bits):
    """Generate a random prime number with 'bits' bits."""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Ensure it's odd and has the right bit length
        if is_prime(candidate):
            return candidate

def is_prime(n, k=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test k rounds
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# ----------------------------
# Paillier Encryption & Decryption
# ----------------------------

def encrypt(pub_key, m):
    n, g = pub_key
    n_square = n * n
    r = random.randrange(1, n)  # random r
    while math.gcd(r, n) != 1:
        r = random.randrange(1, n)
    c = (pow(g, m, n_square) * pow(r, n, n_square)) % n_square
    return c

def decrypt(pub_key, priv_key, c):
    n, g = pub_key
    lam, mu = priv_key
    n_square = n * n
    u = pow(c, lam, n_square)
    l_val = L(u, n)
    m = (l_val * mu) % n
    return m

# ----------------------------
# Demo
# ----------------------------
if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keypair(128)

    # Original numbers
    m1, m2 = 15, 25
    print(f"Original numbers: {m1}, {m2}")

    # Encrypt
    c1 = encrypt(public_key, m1)
    c2 = encrypt(public_key, m2)
    print(f"Ciphertexts: c1 = {c1}, c2 = {c2}")

    # Homomorphic addition (ciphertexts multiply mod n^2)
    n, g = public_key
    n_square = n * n
    c_sum = (c1 * c2) % n_square
    print(f"Encrypted sum (ciphertext): {c_sum}")

    # Decrypt the sum
    decrypted_sum = decrypt(public_key, private_key, c_sum)
    print(f"Decrypted sum: {decrypted_sum}")
