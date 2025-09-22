"""
Digital Signature and Cryptography Lab - Unified Python Script
Demonstrates:
1. RSA digital signature
2. ElGamal signature
3. Schnorr signature
4. Diffie-Hellman key exchange
5. Client-server digital signature simulation
6. CIA triad demonstration with RSA + SHA256
"""

# Required library
# pip install pycryptodome

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import random
from Crypto.Util.number import getPrime, inverse
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
import socket
import threading

print("\n--- 1️⃣ RSA Digital Signatures (Alice ↔ Bob) ---\n")

# ---------------- RSA Key Generation ----------------
# Generate RSA key pairs for Alice and Bob
alice_key = RSA.generate(2048)
bob_key = RSA.generate(2048)

# ---------------- Alice Signs a Document ----------------
document = b"Legal Document: Contract Agreement"
# Compute SHA256 hash of document
hash_doc = SHA256.new(document)
# Alice signs the hash using her private key
alice_signature = pkcs1_15.new(alice_key).sign(hash_doc)

# ---------------- Bob Verifies Alice's Signature ----------------
try:
    pkcs1_15.new(alice_key.publickey()).verify(hash_doc, alice_signature)
    print("Alice's signature verified by Bob ✅")
except (ValueError, TypeError):
    print("Signature verification failed ❌")

# ---------------- Bob Signs a Response ----------------
response_doc = b"Response Document: Approved"
hash_resp = SHA256.new(response_doc)
bob_signature = pkcs1_15.new(bob_key).sign(hash_resp)

# ---------------- Alice Verifies Bob's Signature ----------------
try:
    pkcs1_15.new(bob_key.publickey()).verify(hash_resp, bob_signature)
    print("Bob's signature verified by Alice ✅")
except (ValueError, TypeError):
    print("Signature verification failed ❌")


print("\n--- 2️⃣ ElGamal Digital Signature (Simplified) ---\n")

# Generate small prime for demo
p = getPrime(256)
g = 2  # generator
x = random.randint(2, p-2)   # private key
y = pow(g, x, p)             # public key

# Message to sign
m = 123  # as integer
k = random.randint(2, p-2)   # random nonce for signing
r = pow(g, k, p)
s = (inverse(k, p-1) * (m - x*r)) % (p-1)

# Verification
v1 = pow(g, m, p)
v2 = (pow(y, r, p) * pow(r, s, p)) % p
print("ElGamal signature verified ✅" if v1 == v2 else "ElGamal verification failed ❌")


print("\n--- 3️⃣ Schnorr Signature (Simplified) ---\n")

# Small primes for demo
p_s = 23
q_s = 11
g_s = 2
x_s = 6  # private key
y_s = pow(g_s, x_s, p_s)  # public key

# Message
m_s = "Hello"
k_s = 3  # random nonce
r_s = pow(g_s, k_s, p_s)
e_s = int(sha256((str(r_s)+m_s).encode()).hexdigest(), 16) % q_s
s_s = (k_s - x_s*e_s) % q_s

# Verification
v_s = (pow(g_s, s_s, p_s) * pow(y_s, e_s, p_s)) % p_s
e_ver = int(sha256((str(v_s)+m_s).encode()).hexdigest(), 16) % q_s
print("Schnorr signature verified ✅" if e_ver == e_s else "Schnorr verification failed ❌")


print("\n--- 4️⃣ Diffie-Hellman Key Exchange ---\n")

# Shared parameters
p_dh = 23
g_dh = 5

# Alice's private and public keys
a_dh = 6
A_dh = pow(g_dh, a_dh, p_dh)

# Bob's private and public keys
b_dh = 15
B_dh = pow(g_dh, b_dh, p_dh)

# Shared secret computation
alice_secret = pow(B_dh, a_dh, p_dh)
bob_secret = pow(A_dh, b_dh, p_dh)
print("Shared secret matches ✅" if alice_secret == bob_secret else "Shared secret mismatch ❌")


print("\n--- 5️⃣ Client-Server Digital Signature Simulation ---\n")

# ---------------- Server Code ----------------
def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(1)
    print("Server listening on port 5000...")
    conn, addr = server_socket.accept()
    data = conn.recv(2048)
    message, signature = data.split(b'||')
    # Verify signature using Alice's public key
    hash_msg = SHA256.new(message)
    try:
        pkcs1_15.new(alice_key.publickey()).verify(hash_msg, signature)
        print("Server verified Alice's signature ✅")
    except:
        print("Server failed to verify signature ❌")
    conn.close()
    server_socket.close()

# ---------------- Client Code ----------------
def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5000))
    message = b"Hello Server"
    hash_msg = SHA256.new(message)
    signature = pkcs1_15.new(alice_key).sign(hash_msg)
    client_socket.send(message + b'||' + signature)
    client_socket.close()

# Run server and client in threads
server_thread = threading.Thread(target=server)
server_thread.start()
client_thread = threading.Thread(target=client)
client_thread.start()
server_thread.join()
client_thread.join()


print("\n--- 6️⃣ CIA Triad Demonstration (RSA + SHA256) ---\n")

# ---------------- Confidentiality ----------------
cipher = PKCS1_OAEP.new(bob_key.publickey())
encrypted_msg = cipher.encrypt(b"Secret Message")

# ---------------- Integrity & Authentication ----------------
hash_msg = SHA256.new(b"Secret Message")
signature = pkcs1_15.new(alice_key).sign(hash_msg)

# ---------------- Decrypt & Verify ----------------
decipher = PKCS1_OAEP.new(bob_key)
message_decrypted = decipher.decrypt(encrypted_msg)
try:
    pkcs1_15.new(alice_key.publickey()).verify(SHA256.new(message_decrypted), signature)
    print("CIA triad verified: Confidentiality, Integrity, Authentication ✅")
except:
    print("CIA triad verification failed ❌")

print("\n--- End of Lab Exercises ---")
