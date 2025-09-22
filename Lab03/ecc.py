from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# -------------------------------
# Generate ECC key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# User message
message = b"Secure Transactions"

# -------------------------------
# --- Encryption ---
# Generate ephemeral key for ECIES
ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)

# Derive symmetric AES key from shared key
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'ecies',
).derive(shared_key)

# Encrypt using AES-256-CBC
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
encryptor = cipher.encryptor()

# Pad message to 16 bytes
pad_len = 16 - len(message) % 16
padded_message = message + bytes([pad_len] * pad_len)

ciphertext = encryptor.update(padded_message) + encryptor.finalize()
print("Ciphertext (hex):", ciphertext.hex().upper())

# -------------------------------
# --- Decryption ---
# Use ephemeral public key to derive same shared key
shared_key_dec = ephemeral_private_key.exchange(ec.ECDH(), public_key)

derived_key_dec = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'ecies',
).derive(shared_key_dec)

cipher_dec = Cipher(algorithms.AES(derived_key_dec), modes.CBC(iv))
decryptor = cipher_dec.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

# Unpad
pad_len = decrypted_padded[-1]
decrypted = decrypted_padded[:-pad_len]
print("Decrypted message:", decrypted.decode())
