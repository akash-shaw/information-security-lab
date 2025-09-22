import os
import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# -----------------------------
# Helper Functions
def aes_encrypt_file(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = 16 - len(data) % 16
    data_padded = data + bytes([pad_len]*pad_len)
    ciphertext = cipher.encrypt(data_padded)
    return ciphertext, key, iv

def aes_decrypt_file(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_padded = cipher.decrypt(ciphertext)
    pad_len = data_padded[-1]
    return data_padded[:-pad_len]

# -----------------------------
# RSA Implementation
print("=== RSA 2048-bit ===")
start = time.time()
rsa_key = RSA.generate(2048)
key_gen_time_rsa = time.time() - start
rsa_pub = rsa_key.publickey()
rsa_cipher = PKCS1_OAEP.new(rsa_pub)

# Encrypt AES key with RSA
file_path = "testfile_1MB.bin"  # Example file
ciphertext, aes_key, iv = aes_encrypt_file(file_path)

start = time.time()
encrypted_aes_key_rsa = rsa_cipher.encrypt(aes_key)
enc_time_rsa = time.time() - start

# Decrypt AES key
rsa_decipher = PKCS1_OAEP.new(rsa_key)
start = time.time()
decrypted_aes_key_rsa = rsa_decipher.decrypt(encrypted_aes_key_rsa)
dec_time_rsa = time.time() - start

# Decrypt file
decrypted_file_rsa = aes_decrypt_file(ciphertext, decrypted_aes_key_rsa, iv)
assert decrypted_file_rsa == open(file_path, "rb").read()

print(f"RSA Key Generation Time: {key_gen_time_rsa:.4f}s")
print(f"RSA AES Key Encryption Time: {enc_time_rsa:.4f}s")
print(f"RSA AES Key Decryption Time: {dec_time_rsa:.4f}s")

# -----------------------------
# ECC Implementation (ECIES-like)
print("\n=== ECC secp256r1 ===")
start = time.time()
ecc_private_key = ec.generate_private_key(ec.SECP256R1())
ecc_public_key = ecc_private_key.public_key()
key_gen_time_ecc = time.time() - start

# Derive shared key for AES encryption
ephemeral_key = ec.generate_private_key(ec.SECP256R1())
shared_key = ephemeral_key.exchange(ec.ECDH(), ecc_public_key)

derived_aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'file-transfer'
).derive(shared_key)

start = time.time()
# Encrypt AES key with derived ECC key using AES (simulated ECIES)
iv_ecc = get_random_bytes(16)
cipher = Cipher(algorithms.AES(derived_aes_key), modes.CBC(iv_ecc))
encryptor = cipher.encryptor()
pad_len = 16 - len(aes_key) % 16
aes_key_padded = aes_key + bytes([pad_len]*pad_len)
encrypted_aes_key_ecc = encryptor.update(aes_key_padded) + encryptor.finalize()
enc_time_ecc = time.time() - start

# Decrypt AES key
shared_key_dec = ephemeral_key.exchange(ec.ECDH(), ecc_public_key)
derived_aes_key_dec = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'file-transfer'
).derive(shared_key_dec)

cipher_dec = Cipher(algorithms.AES(derived_aes_key_dec), modes.CBC(iv_ecc))
decryptor = cipher_dec.decryptor()
decrypted_key_padded = decryptor.update(encrypted_aes_key_ecc) + decryptor.finalize()
pad_len = decrypted_key_padded[-1]
decrypted_aes_key_ecc = decrypted_key_padded[:-pad_len]
dec_time_ecc = time.time() - start

# Verify
assert decrypted_aes_key_ecc == aes_key
print(f"ECC Key Generation Time: {key_gen_time_ecc:.4f}s")
print(f"ECC AES Key Encryption Time: {enc_time_ecc:.4f}s")
print(f"ECC AES Key Decryption Time: {dec_time_ecc:.4f}s")
