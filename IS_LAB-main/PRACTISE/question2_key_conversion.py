"""
Question 2: Public Key to Private Key Conversion
Converting public key of one encryption form to private key of other encryption form
RSA Key Generation and Conversion
"""

import random
import math

def gcd(a, b):
    """Calculate Greatest Common Divisor"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """Calculate modular multiplicative inverse"""
    if gcd(a, m) != 1:
        return None
    
    # Extended Euclidean Algorithm
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    _, x, _ = extended_gcd(a, m)
    return (x % m + m) % m

def is_prime(n):
    """Check if number is prime"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

def generate_prime(bits=8):
    """Generate a random prime number"""
    while True:
        num = random.randint(2**(bits-1), 2**bits - 1)
        if is_prime(num):
            return num

def generate_rsa_keys():
    """Generate RSA public and private key pairs"""
    # Step 1: Generate two prime numbers
    p = generate_prime(8)
    q = generate_prime(8)
    
    # Ensure p and q are different
    while p == q:
        q = generate_prime(8)
    
    # Step 2: Calculate n = p * q
    n = p * q
    
    # Step 3: Calculate Euler's totient function φ(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)
    
    # Step 4: Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = 65537  # Common choice for e
    if e >= phi_n or gcd(e, phi_n) != 1:
        e = 3
        while gcd(e, phi_n) != 1:
            e += 2
    
    # Step 5: Calculate d = e^(-1) mod φ(n)
    d = mod_inverse(e, phi_n)
    
    return {
        'p': p,
        'q': q,
        'n': n,
        'phi_n': phi_n,
        'e': e,  # Public exponent
        'd': d,  # Private exponent
        'public_key': (n, e),
        'private_key': (n, d)
    }

def rsa_encrypt(message, public_key):
    """Encrypt message using RSA public key"""
    n, e = public_key
    # Convert message to number (for demo, using ASCII values)
    if isinstance(message, str):
        message = ord(message[0])  # Take first character for simplicity
    
    ciphertext = pow(message, e, n)
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    """Decrypt message using RSA private key"""
    n, d = private_key
    plaintext = pow(ciphertext, d, n)
    return plaintext

def convert_public_to_private_info(public_key, p, q):
    """Convert public key information to derive private key components"""
    n, e = public_key
    
    # Verify that n = p * q
    if n != p * q:
        raise ValueError("Invalid p and q for given public key")
    
    # Calculate φ(n)
    phi_n = (p - 1) * (q - 1)
    
    # Calculate private exponent d
    d = mod_inverse(e, phi_n)
    
    return {
        'private_exponent': d,
        'private_key': (n, d),
        'factors': (p, q),
        'phi_n': phi_n
    }

# Example usage
if __name__ == "__main__":
    print("RSA Key Generation and Public-Private Key Conversion")
    print("=" * 55)
    
    # Generate RSA keys
    keys = generate_rsa_keys()
    
    print(f"Prime p: {keys['p']}")
    print(f"Prime q: {keys['q']}")
    print(f"Modulus n: {keys['n']}")
    print(f"Phi(n): {keys['phi_n']}")
    print(f"Public key (n, e): {keys['public_key']}")
    print(f"Private key (n, d): {keys['private_key']}")
    
    # Demonstrate encryption/decryption
    message = "A"
    print(f"\nOriginal message: {message}")
    
    encrypted = rsa_encrypt(message, keys['public_key'])
    print(f"Encrypted: {encrypted}")
    
    decrypted = rsa_decrypt(encrypted, keys['private_key'])
    print(f"Decrypted: {chr(decrypted)}")
    
    # Demonstrate public to private conversion
    print("\n" + "="*55)
    print("Converting Public Key to Private Key Components")
    print("="*55)
    
    conversion_result = convert_public_to_private_info(
        keys['public_key'], 
        keys['p'], 
        keys['q']
    )
    
    print(f"Given public key: {keys['public_key']}")
    print(f"Given factors p={keys['p']}, q={keys['q']}")
    print(f"Derived private exponent: {conversion_result['private_exponent']}")
    print(f"Derived private key: {conversion_result['private_key']}")
    print(f"Verification: d * e mod φ(n) = {(keys['d'] * keys['e']) % keys['phi_n']}")
