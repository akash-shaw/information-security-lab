from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter

# Parameters
key = b"0123456789ABCDEF0123456789ABCDEF"  # 32 chars = 16 bytes (AES-128)
nonce = b"0000000000000000"  # 16 chars = 8 bytes
plaintext = "Cryptography Lab Exercise"

# Create AES-CTR cipher
ctr = Counter.new(64, prefix=nonce, initial_value=0)
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

# Encrypt
ciphertext = cipher.encrypt(plaintext.encode())
print("Ciphertext (hex):", ciphertext.hex().upper())

# Decrypt (new counter instance needed)
ctr_dec = Counter.new(64, prefix=nonce, initial_value=0)
decipher = AES.new(key, AES.MODE_CTR, counter=ctr_dec)
decrypted = decipher.decrypt(ciphertext).decode()
print("Decrypted text:", decrypted)
