"""
Question 3: AES/DES/RSA Implementation
Comprehensive implementation of symmetric and asymmetric encryption algorithms
"""

from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class CryptoImplementation:
    def __init__(self):
        pass
    
    # AES Implementation
    def aes_encrypt(self, plaintext, key):
        """Encrypt using AES in CBC mode"""
        # Ensure key is 16, 24, or 32 bytes
        if len(key) not in [16, 24, 32]:
            key = key.ljust(16, '0')[:16]  # Pad or truncate to 16 bytes
        
        key_bytes = key.encode('utf-8')
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Generate random IV
        iv = get_random_bytes(AES.block_size)
        
        # Create cipher object
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        
        # Pad plaintext and encrypt
        padded_plaintext = pad(plaintext_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # Combine IV and ciphertext
        encrypted_data = iv + ciphertext
        
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def aes_decrypt(self, encrypted_data, key):
        """Decrypt using AES in CBC mode"""
        # Ensure key is 16, 24, or 32 bytes
        if len(key) not in [16, 24, 32]:
            key = key.ljust(16, '0')[:16]
        
        key_bytes = key.encode('utf-8')
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract IV and ciphertext
        iv = encrypted_bytes[:AES.block_size]
        ciphertext = encrypted_bytes[AES.block_size:]
        
        # Create cipher object and decrypt
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        plaintext = unpad(padded_plaintext, AES.block_size)
        
        return plaintext.decode('utf-8')
    
    # DES Implementation
    def des_encrypt(self, plaintext, key):
        """Encrypt using DES in CBC mode"""
        # DES key must be 8 bytes
        if len(key) != 8:
            key = key.ljust(8, '0')[:8]
        
        key_bytes = key.encode('utf-8')
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Generate random IV
        iv = get_random_bytes(DES.block_size)
        
        # Create cipher object
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        
        # Pad plaintext and encrypt
        padded_plaintext = pad(plaintext_bytes, DES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # Combine IV and ciphertext
        encrypted_data = iv + ciphertext
        
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def des_decrypt(self, encrypted_data, key):
        """Decrypt using DES in CBC mode"""
        # DES key must be 8 bytes
        if len(key) != 8:
            key = key.ljust(8, '0')[:8]
        
        key_bytes = key.encode('utf-8')
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract IV and ciphertext
        iv = encrypted_bytes[:DES.block_size]
        ciphertext = encrypted_bytes[DES.block_size:]
        
        # Create cipher object and decrypt
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove padding
        plaintext = unpad(padded_plaintext, DES.block_size)
        
        return plaintext.decode('utf-8')
    
    # RSA Implementation
    def generate_rsa_keys(self, key_size=2048):
        """Generate RSA key pair"""
        key = RSA.generate(key_size)
        private_key = key
        public_key = key.publickey()
        
        return private_key, public_key
    
    def rsa_encrypt(self, plaintext, public_key):
        """Encrypt using RSA public key"""
        cipher = PKCS1_OAEP.new(public_key)
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = cipher.encrypt(plaintext_bytes)
        
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def rsa_decrypt(self, encrypted_data, private_key):
        """Decrypt using RSA private key"""
        cipher = PKCS1_OAEP.new(private_key)
        encrypted_bytes = base64.b64decode(encrypted_data)
        plaintext_bytes = cipher.decrypt(encrypted_bytes)
        
        return plaintext_bytes.decode('utf-8')

# Simple implementations without external libraries (for educational purposes)
class SimpleCrypto:
    def simple_aes_substitute(self, text, key):
        """Simple substitution cipher (AES-like concept)"""
        result = ""
        key_index = 0
        
        for char in text:
            if char.isalpha():
                # Simple substitution using key
                shift = ord(key[key_index % len(key)]) % 26
                if char.isupper():
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                key_index += 1
            else:
                result += char
        
        return result
    
    def simple_rsa_demo(self):
        """Simple RSA demonstration with small numbers"""
        # Choose small primes for demonstration
        p, q = 61, 53
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        # Choose e
        e = 17
        
        # Calculate d
        d = pow(e, -1, phi_n)
        
        return {
            'p': p, 'q': q, 'n': n,
            'public_key': (n, e),
            'private_key': (n, d)
        }

# Example usage
if __name__ == "__main__":
    print("Cryptographic Algorithms Implementation")
    print("=" * 45)
    
    # Try with external libraries first
    try:
        crypto = CryptoImplementation()
        
        # AES Example
        print("\n1. AES Encryption/Decryption:")
        plaintext = "Hello, World!"
        aes_key = "secretkey123456"
        
        aes_encrypted = crypto.aes_encrypt(plaintext, aes_key)
        print(f"AES Encrypted: {aes_encrypted}")
        
        aes_decrypted = crypto.aes_decrypt(aes_encrypted, aes_key)
        print(f"AES Decrypted: {aes_decrypted}")
        
        # DES Example
        print("\n2. DES Encryption/Decryption:")
        des_key = "12345678"  # 8 bytes for DES
        
        des_encrypted = crypto.des_encrypt(plaintext, des_key)
        print(f"DES Encrypted: {des_encrypted}")
        
        des_decrypted = crypto.des_decrypt(des_encrypted, des_key)
        print(f"DES Decrypted: {des_decrypted}")
        
        # RSA Example
        print("\n3. RSA Encryption/Decryption:")
        private_key, public_key = crypto.generate_rsa_keys(1024)  # Smaller key for demo
        
        rsa_plaintext = "RSA Test"
        rsa_encrypted = crypto.rsa_encrypt(rsa_plaintext, public_key)
        print(f"RSA Encrypted: {rsa_encrypted[:50]}...")
        
        rsa_decrypted = crypto.rsa_decrypt(rsa_encrypted, private_key)
        print(f"RSA Decrypted: {rsa_decrypted}")
        
    except ImportError:
        print("PyCryptodome library not found. Using simple implementations...")
        
        # Use simple implementations
        simple_crypto = SimpleCrypto()
        
        print("\n1. Simple Substitution (AES concept):")
        plaintext = "HELLO"
        key = "KEY"
        
        encrypted = simple_crypto.simple_aes_substitute(plaintext, key)
        print(f"Simple Encrypted: {encrypted}")
        
        print("\n2. Simple RSA Demo:")
        rsa_demo = simple_crypto.simple_rsa_demo()
        print(f"RSA Demo Keys: {rsa_demo}")
        
        # Simple RSA encryption/decryption
        message = 65  # ASCII value of 'A'
        n, e = rsa_demo['public_key']
        n, d = rsa_demo['private_key']
        
        encrypted_msg = pow(message, e, n)
        decrypted_msg = pow(encrypted_msg, d, n)
        
        print(f"Message: {message} ('{chr(message)}')")
        print(f"Encrypted: {encrypted_msg}")
        print(f"Decrypted: {decrypted_msg} ('{chr(decrypted_msg)}')")
        
    print("\nNote: Install 'pycryptodome' for full functionality:")
    print("pip install pycryptodome")
