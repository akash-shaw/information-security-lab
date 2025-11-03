import random
import math

# ----------------------------
# Utility functions
# ----------------------------
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """Modular inverse using Extended Euclidean Algorithm"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)

def is_prime(n, k=20):
    """Miller–Rabin primality test"""
    if n < 2:
        return False
    # small primes
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    # write n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def get_prime(bits):
    """Generate a random prime with 'bits' bits"""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1
        if is_prime(candidate):
            return candidate

# ----------------------------
# RSA Key Generation
# ----------------------------
def generate_keys(bits=64):
    p = get_prime(bits // 2)
    q = get_prime(bits // 2)
    while q == p:
        q = get_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        # choose another e if not coprime
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = modinv(e, phi)
    return (e, n), (d, n)

# ----------------------------
# RSA Encryption / Decryption
# ----------------------------
def encrypt(pub_key, m):
    e, n = pub_key
    return pow(m, e, n)

def decrypt(priv_key, c):
    d, n = priv_key
    return pow(c, d, n)

# ----------------------------
# Demo
# ----------------------------
if __name__ == "__main__":
    # Generate RSA keys
    public_key, private_key = generate_keys(64)

    # Original messages
    m1, m2 = 7, 3
    print(f"Original messages: {m1}, {m2}")

    # Encrypt
    c1 = encrypt(public_key, m1)
    c2 = encrypt(public_key, m2)
    print(f"Ciphertexts: c1 = {c1}, c2 = {c2}")

    # Homomorphic multiplication (ciphertext multiplication mod n)
    e, n = public_key
    c_mul = (c1 * c2) % n
    print(f"Encrypted multiplication (ciphertext): {c_mul}")

    # Decrypt result
    decrypted_mul = decrypt(private_key, c_mul)
    print(f"Decrypted product: {decrypted_mul}")
