from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad

# Parameters
key = b"A1B2C3D4"         # 8 bytes
iv = b"12345678"          # 8 bytes
plaintext = "Secure Communication"

# Create cipher (CBC mode)
cipher = DES.new(key, DES.MODE_CBC, iv)

# Pad and encrypt
ciphertext = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
print("Ciphertext (hex):", ciphertext.hex().upper())

# Decrypt
decipher = DES.new(key, DES.MODE_CBC, iv)
decrypted = unpad(decipher.decrypt(ciphertext), DES.block_size)
print("Decrypted text:", decrypted.decode())
