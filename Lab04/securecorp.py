# SecureCorp is a large enterprise with multiple subsidiaries and business units located
# across different geographical regions. As part of their digital transformation initiative,
# the IT team at SecureCorp has been tasked with building a secure and scalable
# communication system to enable seamless collaboration and information sharing
# between their various subsystems.
# The enterprise system consists of the following key subsystems:
# 1. Finance System (System A): Responsible for all financial record-keeping, accounting,
# and reporting.
# 2. HR System (System B): Manages employee data, payroll, and personnel related
# processes.
# 3. Supply Chain Management (System C): Coordinates the flow of goods, services, and
# information across the organization's supply chain
# These subsystems need to communicate securely and exchange critical documents, such
# financial reports, employee contracts, and procurement orders, to ensure the enterprise's
# overall efficiency.
# The IT team at SecureCorp has identified the following requirements for the secure
# communication and document signing solution:
# 1. Secure Communication: The subsystems must be able to establish secure
# communication channels using a combination of RSA encryption and Diffie-Hellman key exchange.



from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
import secrets

# -----------------------------
# Subsystem A generates RSA key
rsa_A = RSA.generate(2048)
rsa_pub_A = rsa_A.publickey()

# Subsystem B generates RSA key
rsa_B = RSA.generate(2048)
rsa_pub_B = rsa_B.publickey()

# -----------------------------
# Diffie-Hellman (simplified modular example)
p = 0xFFFFFFFEFFFFFC2F  # small prime for demonstration
g = 2

# Subsystem A DH private & public
dh_priv_A = secrets.randbelow(p-2) + 1
dh_pub_A = pow(g, dh_priv_A, p)

# Subsystem B DH private & public
dh_priv_B = secrets.randbelow(p-2) + 1
dh_pub_B = pow(g, dh_priv_B, p)

# Exchange DH public keys (optionally encrypt with RSA)
shared_key_A = pow(dh_pub_B, dh_priv_A, p)
shared_key_B = pow(dh_pub_A, dh_priv_B, p)
assert shared_key_A == shared_key_B
aes_session_key = SHA256.new(shared_key_A.to_bytes(32, 'big')).digest()

# -----------------------------
# Subsystem A encrypts a document for B
document = b"Confidential Financial Report Q3"
iv = get_random_bytes(16)
cipher = AES.new(aes_session_key, AES.MODE_CBC, iv)
pad_len = 16 - len(document) % 16
ciphertext = cipher.encrypt(document + bytes([pad_len]*pad_len))

# Sign the document
hash_doc = SHA256.new(document)
signature = pkcs1_15.new(rsa_A).sign(hash_doc)

# -----------------------------
# Subsystem B decrypts document
dec_cipher = AES.new(aes_session_key, AES.MODE_CBC, iv)
padded_doc = dec_cipher.decrypt(ciphertext)
document_decrypted = padded_doc[:-padded_doc[-1]]

# Verify signature
hash_doc_received = SHA256.new(document_decrypted)
try:
    pkcs1_15.new(rsa_pub_A).verify(hash_doc_received, signature)
    print("Signature verified. Document is authentic.")
except (ValueError, TypeError):
    print("Signature verification failed!")

print("Decrypted Document:", document_decrypted.decode())
