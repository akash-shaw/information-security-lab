from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes


def generate_keys():
    key = RSA.generate(2048)
    return key


def encrypt(message, public_key):
    n = public_key.n
    e = public_key.e
    ciphertext = pow(message, e, n)
    return ciphertext


def decrypt(ciphertext, private_key):
    n = private_key.n
    d = private_key.d
    plaintext = pow(ciphertext, d, n)
    return plaintext


# Generate keys
key = generate_keys()
public_key = key.publickey()
private_key = key

# Original values
m1 = 7
m2 = 3

# Encrypt
c1 = encrypt(m1, public_key)
c2 = encrypt(m2, public_key)
print(f"Ciphertext 1: {c1}")
print(f"Ciphertext 2: {c2}")

# Homomorphic multiplication
c_product = (c1 * c2) % public_key.n
print(f"Encrypted product: {c_product}")

# Decrypt result
decrypted_product = decrypt(c_product, private_key)
print(f"Decrypted product: {decrypted_product}")

# Verify
expected_product = m1 * m2
print(f"Expected product: {expected_product}")
print(f"Match: {decrypted_product == expected_product}")
