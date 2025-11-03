from Cryptodome.Cipher import DES3
from Cryptodome.Util.Padding import pad, unpad
from binascii import unhexlify

# ----------------------------
# User input
plaintext = input("Enter the message to encrypt: ")

key_hex = input("Enter a 48-character hex key for Triple DES (24 bytes): ")
if len(key_hex) != 48:
    raise ValueError("Key must be exactly 48 hex characters (24 bytes).")

# Convert hex key to bytes
key = unhexlify(key_hex)

# Ensure key is valid for DES3
if not DES3.adjust_key_parity(key):
    key = DES3.adjust_key_parity(key)

# DES3 block size
block_size = 8

# Pad plaintext
data = pad(plaintext.encode(), block_size)

# Create Triple DES cipher in ECB mode
cipher = DES3.new(key, DES3.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(data)
print("\nCiphertext (hex):", ciphertext.hex())

# Decrypt
decipher = DES3.new(key, DES3.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), block_size)
print("Decrypted message:", decrypted.decode())
