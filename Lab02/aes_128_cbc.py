from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

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

# Generate random IV
iv = get_random_bytes(block_size)

# Create AES cipher in CBC mode
cipher = AES.new(key, AES.MODE_CBC, iv)

# Encrypt
data = pad(plaintext.encode(), block_size)
ciphertext = cipher.encrypt(data)

print("\nCiphertext (hex):", ciphertext.hex())
print("IV (hex):", iv.hex())

# Decrypt
decipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = unpad(decipher.decrypt(ciphertext), block_size)
print("Decrypted message:", decrypted.decode())
