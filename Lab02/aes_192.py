from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

# ----------------------------
# AES-192 key must be 24 bytes (192 bits)
key_hex = "FEDCBA9876543210FEDCBA9876543210"
key = bytes.fromhex(key_hex)

# Plaintext
plaintext = "Top Secret Data"  # 16 bytes

# Pad plaintext to 16 bytes (AES block size)
data = pad(plaintext.encode(), 16)

# AES-192 in ECB mode (simplest demonstration)
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt
ciphertext = cipher.encrypt(data)
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt
decipher = AES.new(key, AES.MODE_ECB)
decrypted = unpad(decipher.decrypt(ciphertext), 16)
print("Decrypted message:", decrypted.decode())
