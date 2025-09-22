from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# ----------------------------
# User inputs
plaintext = input("Enter the message to encrypt: ")

key_input = input("Enter an 8-character key: ")
if len(key_input) != 8:
    raise ValueError("DES key must be exactly 8 characters long.")
key = key_input.encode()

# DES block size
block_size = 8

# Convert plaintext to bytes and pad
data = pad(plaintext.encode(), block_size)

# Create DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(data)
print("\nCiphertext (hex):", ciphertext.hex())

# Decrypt
decipher = DES.new(key, DES.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), block_size)
print("Decrypted message:", decrypted.decode())
