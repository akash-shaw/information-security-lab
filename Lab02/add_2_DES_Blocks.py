from Cryptodome.Cipher import DES
from binascii import unhexlify, hexlify

# Key (hex → bytes)
key = bytes.fromhex("A1B2C3D4E5F60708")

# Data blocks (hex → bytes)
block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"

block1 = bytes.fromhex(block1_hex)
block2 = bytes.fromhex(block2_hex)

# Create DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Encrypt both blocks
ciphertext1 = cipher.encrypt(block1[:8]) + cipher.encrypt(block1[8:16]) + cipher.encrypt(block1[16:24]) + cipher.encrypt(block1[24:32]) + cipher.encrypt(block1[32:40])
ciphertext2 = cipher.encrypt(block2[:8]) + cipher.encrypt(block2[8:16]) + cipher.encrypt(block2[16:24]) + cipher.encrypt(block2[24:32]) + cipher.encrypt(block2[32:40])

print("Ciphertext Block 1:", ciphertext1.hex().upper())
print("Ciphertext Block 2:", ciphertext2.hex().upper())

# Decrypt
decipher = DES.new(key, DES.MODE_ECB)
decrypted1 = decipher.decrypt(ciphertext1)
decrypted2 = decipher.decrypt(ciphertext2)

print("Decrypted Block 1:", decrypted1.decode(errors="ignore"))
print("Decrypted Block 2:", decrypted2.decode(errors="ignore"))
