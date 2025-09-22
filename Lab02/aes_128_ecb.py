from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ----------------------------
# User input
plaintext = input("Enter the message to encrypt: ")
key_input = input("Enter a 32-character hex key (16 bytes, e.g., 0123456789ABCDEF0123456789ABCDEF): ")

if len(key_input) != 32:
    raise ValueError("AES-128 key must be exactly 32 hex characters (16 bytes).")

# Convert hex string to bytes
key = bytes.fromhex(key_input)

# AES block size
block_size = 16

# Pad plaintext to 16 bytes
data = pad(plaintext.encode(), block_size)

# Create AES cipher in ECB mode
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(data)
print("\nCiphertext (hex):", ciphertext.hex())

# Decrypt
decipher = AES.new(key, AES.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), block_size)
print("Decrypted message:", decrypted.decode())
