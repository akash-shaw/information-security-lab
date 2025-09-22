from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

# Generate RSA key pair
key_size = 2048
key = RSA.generate(key_size)

# Extract keys
public_key = key.publickey()
private_key = key

print("Public key (n, e):", (public_key.n, public_key.e))
print("Private key (n, d):", (private_key.n, private_key.d))

# -------------------------------
# User input message
message = input("\nEnter the message to encrypt: ").encode()

# Encrypt with public key
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(message)
print("\nCiphertext (hex):", ciphertext.hex().upper())

# Decrypt with private key
decipher = PKCS1_OAEP.new(private_key)
decrypted = decipher.decrypt(ciphertext)
print("Decrypted message:", decrypted.decode())
