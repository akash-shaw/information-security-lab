from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, time

# -------------------------------
# Generate recipient key pair (secp256r1)
recipient_private_key = ec.generate_private_key(ec.SECP256R1())
recipient_public_key = recipient_private_key.public_key()

# -------------------------------
# Example patient data
patient_data = b"Sensitive Patient Record: John Doe, DOB 1990-01-01, Blood Type O+"

# Convert patient data to AES encryption
aes_key = os.urandom(32)  # AES-256
iv = os.urandom(16)
pad_len = 16 - len(patient_data) % 16
padded_data = patient_data + bytes([pad_len]*pad_len)

# Encrypt patient data using AES
start_time = time.time()
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext_data = encryptor.update(padded_data) + encryptor.finalize()
aes_encrypt_time = time.time() - start_time

# -------------------------------
# Encrypt AES key using ECC-ElGamal (ECIES-style)
start_time = time.time()
ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
shared_key = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

# Derive AES key to encrypt the AES key
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'ecc-elgamal'
).derive(shared_key)

iv_key = os.urandom(16)
cipher_aeskey = Cipher(algorithms.AES(derived_key), modes.CBC(iv_key))
encryptor_key = cipher_aeskey.encryptor()
pad_len_key = 16 - len(aes_key) % 16
aes_key_padded = aes_key + bytes([pad_len_key]*pad_len_key)
ciphertext_key = encryptor_key.update(aes_key_padded) + encryptor_key.finalize()
ecc_encrypt_time = time.time() - start_time

# -------------------------------
# Decrypt AES key
start_time = time.time()
shared_key_dec = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
derived_key_dec = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'ecc-elgamal'
).derive(shared_key_dec)

cipher_aeskey_dec = Cipher(algorithms.AES(derived_key_dec), modes.CBC(iv_key))
decryptor_key = cipher_aeskey_dec.decryptor()
aes_key_padded_dec = decryptor_key.update(ciphertext_key) + decryptor_key.finalize()
pad_len_key = aes_key_padded_dec[-1]
aes_key_dec = aes_key_padded_dec[:-pad_len_key]
ecc_decrypt_time = time.time() - start_time

# -------------------------------
# Decrypt patient data
cipher_dec = Cipher(algorithms.AES(aes_key_dec), modes.CBC(iv))
decryptor = cipher_dec.decryptor()
padded_patient_data = decryptor.update(ciphertext_data) + decryptor.finalize()
pad_len_data = padded_patient_data[-1]
decrypted_patient_data = padded_patient_data[:-pad_len_data]

# -------------------------------
# Results
print("Patient Data:", decrypted_patient_data.decode())
print("AES Encryption Time: {:.6f}s".format(aes_encrypt_time))
print("ECC Key Encryption Time: {:.6f}s".format(ecc_encrypt_time))
print("ECC Key Decryption Time: {:.6f}s".format(ecc_decrypt_time))
