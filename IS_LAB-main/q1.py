from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import random

# ---------------------------
# Diffie-Hellman Parameters
# ---------------------------
# Large prime (2048-bit prime recommended, smaller for demo)
DH_PRIME = 0xF7E75FDC469067FFDC4E847C51F452DF
DH_BASE = 5

def dh_generate_private_key():
    return random.randint(2, DH_PRIME - 2)

def dh_generate_public_key(priv_key):
    return pow(DH_BASE, priv_key, DH_PRIME)

def dh_generate_shared_key(their_pub, my_priv):
    return pow(their_pub, my_priv, DH_PRIME)

# ---------------------------
# Key Manager
# ---------------------------
class KeyManager:
    def __init__(self):
        self.subsystems = {}
        self.revoked = set()  # revoked public keys (by subsystem name)

    def generate_rsa_keys(self, name):
        key = RSA.generate(2048)
        self.subsystems[name] = {
            'rsa_priv': key,
            'rsa_pub': key.publickey(),
            'dh_priv': dh_generate_private_key(),
            'dh_pub': None,
            'dh_shared_keys': {},  # shared keys with other subsystems
        }
        self.subsystems[name]['dh_pub'] = dh_generate_public_key(self.subsystems[name]['dh_priv'])

    def revoke_key(self, name):
        self.revoked.add(name)

    def is_revoked(self, name):
        return name in self.revoked

    def get_rsa_pub(self, name):
        return self.subsystems[name]['rsa_pub']

    def get_dh_pub(self, name):
        return self.subsystems[name]['dh_pub']

    def get_rsa_priv(self, name):
        return self.subsystems[name]['rsa_priv']

    def get_dh_priv(self, name):
        return self.subsystems[name]['dh_priv']

    def generate_shared_keys(self):
        # Each subsystem computes shared DH keys with others
        for name1, data1 in self.subsystems.items():
            for name2, data2 in self.subsystems.items():
                if name1 != name2:
                    shared = dh_generate_shared_key(data2['dh_pub'], data1['dh_priv'])
                    # Hash the shared secret to get AES key
                    shared_key = SHA256.new(shared.to_bytes(256, 'big')).digest()
                    data1['dh_shared_keys'][name2] = shared_key

    def get_shared_key(self, from_name, to_name):
        return self.subsystems[from_name]['dh_shared_keys'][to_name]

# ---------------------------
# Secure Communication
# ---------------------------

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag

def aes_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def rsa_sign(priv_key, message):
    h = SHA256.new(message)
    signature = pkcs1_15.new(priv_key).sign(h)
    return signature

def rsa_verify(pub_key, message, signature):
    h = SHA256.new(message)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ---------------------------
# Example usage and testing
# ---------------------------

def main():
    km = KeyManager()

    # Generate keys for subsystems A, B, C
    for system in ['Finance', 'HR', 'SupplyChain']:
        km.generate_rsa_keys(system)

    # Generate DH shared AES keys between all systems
    km.generate_shared_keys()

    # Simulate Finance -> HR secure message exchange
    sender = 'Finance'
    receiver = 'HR'

    if km.is_revoked(sender) or km.is_revoked(receiver):
        print(f"Communication blocked due to revoked key.")
        return

    message = b"Confidential Financial Report Q3 2025"

    # Encrypt message using shared AES key (DH)
    shared_key = km.get_shared_key(sender, receiver)
    nonce, ciphertext, tag = aes_encrypt(shared_key, message)

    # Sign the ciphertext with sender's RSA private key
    signature = rsa_sign(km.get_rsa_priv(sender), ciphertext)

    # Receiver verifies signature using sender's RSA public key
    valid = rsa_verify(km.get_rsa_pub(sender), ciphertext, signature)

    print(f"Signature valid? {valid}")

    if not valid:
        print("Signature invalid! Abort.")
        return

    # Decrypt message using shared AES key (DH)
    decrypted = aes_decrypt(shared_key, nonce, ciphertext, tag)

    print(f"Decrypted message at {receiver}: {decrypted.decode()}")

    # Demonstrate revocation
    print("\nRevoking HR keys...")
    km.revoke_key('HR')

    if km.is_revoked('HR'):
        print("HR keys revoked. Communication blocked.")

    # Trying to send message to revoked system
    if km.is_revoked(receiver):
        print(f"Cannot send to revoked system: {receiver}")

if __name__ == "__main__":
    main()
