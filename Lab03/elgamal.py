import random

# -------------------------------
# Example ElGamal parameters (small for demo)
p = 30803               # prime
g = 2                   # generator
x = 7890                # private key
h = pow(g, x, p)        # public key component

message = "Confidential Data"

# Convert message to integer
m_int = int.from_bytes(message.encode(), byteorder='big')
if m_int >= p:
    raise ValueError("Message integer too large for chosen prime p.")

# -------------------------------
# Encryption
y = random.randint(1, p-2)          # random ephemeral key
c1 = pow(g, y, p)
c2 = (m_int * pow(h, y, p)) % p
ciphertext = (c1, c2)
print("Ciphertext:", ciphertext)

# -------------------------------
# Decryption
s = pow(c1, x, p)
# Compute modular inverse of s
s_inv = pow(s, -1, p)
m_decrypted_int = (c2 * s_inv) % p

# Convert integer back to string
m_decrypted = m_decrypted_int.to_bytes((m_decrypted_int.bit_length() + 7) // 8, byteorder='big').decode()
print("Decrypted message:", m_decrypted)
