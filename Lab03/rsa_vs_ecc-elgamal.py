import os
import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# -------------------------------
# Helper functions
def aes_encrypt_decrypt(data, key=None, iv=None, mode='encrypt'):
    if key is None:
        key = get_random_bytes(32)  # AES-256
    if iv is None:
        iv = get_random_bytes(16)
    pad_len = 16 - len(data) % 16
    if mode == 'encrypt':
        data_padded = data + bytes([pad_len]*pad_len)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(data_padded)
        return ciphertext, key, iv
    elif mode == 'decrypt':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data_padded = cipher.decrypt(data)
        return data_padded[:-data_padded[-1]]

# -------------------------------
# Messages of varying sizes
messages = {
    "1KB": os.urandom(1024),
    "10KB": os.urandom(10*1024)
}

results = {}

for size, message in messages.items():
    print(f"\n--- Message Size: {size} ---")

    # -------------------------------
    # RSA 2048-bit
    start = time.time()
    rsa_key = RSA.generate(2048)
    rsa_pub = rsa_key.publickey()
    key_gen_time = time.time() - start

    # Encrypt message using AES
    ciphertext, aes_key, iv = aes_encrypt_decrypt(message)

    # Encrypt AES key with RSA
    rsa_cipher = PKCS1_OAEP.new(rsa_pub)
    start = time.time()
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    enc_time = time.time() - start

    # Decrypt AES key
    rsa_decipher = PKCS1_OAEP.new(rsa_key)
    start = time.time()
    decrypted_aes_key = rsa_decipher.decrypt(encrypted_aes_key)
    dec_time = time.time() - start

    # Decrypt message
    decrypted_message = aes_encrypt_decrypt(ciphertext, decrypted_aes_key, iv, mode='decrypt')
    assert decrypted_message == message

    results[f"RSA_{size}"] = (key_gen_time, enc_time, dec_time)
    print(f"RSA - KeyGen: {key_gen_time:.4f}s, AESKey Enc: {enc_time:.4f}s, AESKey Dec: {dec_time:.4f}s")

    # -------------------------------
    # ECC-ElGamal (secp256r1, ECIES-style)
    start = time.time()
    recipient_private_key = ec.generate_private_key(ec.SECP256R1())
    recipient_public_key = recipient_private_key.public_key()
    ecc_keygen_time = time.time() - start

    # Encrypt AES key using ECIES-style
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    start = time.time()
    shared_key = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc-elgamal'
    ).derive(shared_key)

    iv_key = os.urandom(16)
    cipher_aeskey = Cipher(algorithms.AES(derived_key), modes.CBC(iv_key))
    encryptor = cipher_aeskey.encryptor()
    pad_len_key = 16 - len(aes_key) % 16
    aes_key_padded = aes_key + bytes([pad_len_key]*pad_len_key)
    ciphertext_key = encryptor.update(aes_key_padded) + encryptor.finalize()
    ecc_enc_time = time.time() - start

    # Decrypt AES key
    start = time.time()
    shared_key_dec = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
    derived_key_dec = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc-elgamal'
    ).derive(shared_key_dec)

    cipher_aeskey_dec = Cipher(algorithms.AES(derived_key_dec), modes.CBC(iv_key))
    decryptor = cipher_aeskey_dec.decryptor()
    decrypted_key_padded = decryptor.update(ciphertext_key) + decryptor.finalize()
    pad_len_key = decrypted_key_padded[-1]
    decrypted_aes_key = decrypted_key_padded[:-pad_len_key]
    ecc_dec_time = time.time() - start

    # Decrypt message
    decrypted_message = aes_encrypt_decrypt(ciphertext, decrypted_aes_key, iv, mode='decrypt')
    assert decrypted_message == message

    results[f"ECC_{size}"] = (ecc_keygen_time, ecc_enc_time, ecc_dec_time)
    print(f"ECC-ElGamal - KeyGen: {ecc_keygen_time:.4f}s, AESKey Enc: {ecc_enc_time:.4f}s, AESKey Dec: {ecc_dec_time:.4f}s")
