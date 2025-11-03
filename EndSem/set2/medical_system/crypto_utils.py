#!/usr/bin/env python3

"""
Cryptographic utilities for the medical records system.
Implements various cryptographic operations needed by both client and server.
"""

import os
import time
import json
import base64
from typing import Tuple, Dict, Any
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

class CryptoManager:
    """Manages all cryptographic operations for the medical records system"""
    
    def __init__(self):
        self.rsa_key = None
        self.elgamal_key = None
        self.paillier_key = None
    
    def generate_keys(self) -> None:
        """Generate all necessary cryptographic keys"""
        # Generate RSA key pair (2048 bits)
        self.rsa_key = RSA.generate(2048)
        
        # Generate ElGamal key pair
        self.elgamal_key = ElGamal.generate(1024, get_random_bytes)
    
    def get_public_keys(self) -> Dict[str, str]:
        """Export all public keys in a format suitable for transmission"""
        return {
            'rsa': self.rsa_key.publickey().export_key().decode(),
            'elgamal': {
                'p': str(self.elgamal_key.p),
                'g': str(self.elgamal_key.g),
                'y': str(self.elgamal_key.y)
            }
        }
    
    @staticmethod
    def generate_aes_key() -> bytes:
        """Generate a random AES-256 key"""
        return get_random_bytes(32)  # 256 bits = 32 bytes
    
    def encrypt_aes_key(self, aes_key: bytes, recipient_rsa_pub: RSA.RsaKey) -> bytes:
        """Encrypt an AES key using recipient's RSA public key"""
        cipher = PKCS1_OAEP.new(recipient_rsa_pub)
        return cipher.encrypt(aes_key)
    
    def decrypt_aes_key(self, encrypted_key: bytes) -> bytes:
        """Decrypt an AES key using our RSA private key"""
        cipher = PKCS1_OAEP.new(self.rsa_key)
        return cipher.decrypt(encrypted_key)
    
    @staticmethod
    def encrypt_data(data: Dict[str, Any], aes_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM
        Returns (ciphertext, tag)
        """
        # Convert data to JSON string
        data_str = json.dumps(data)
        
        # Generate nonce
        nonce = get_random_bytes(12)
        
        # Create cipher
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt
        ciphertext, tag = cipher.encrypt_and_digest(data_str.encode())
        
        # Combine nonce and ciphertext
        return nonce + ciphertext, tag
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, tag: bytes, aes_key: bytes) -> Dict[str, Any]:
        """Decrypt data using AES-256-GCM"""
        # Split nonce and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # Create cipher
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt
        data = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Parse JSON
        return json.loads(data.decode())
    
    def sign_data(self, data: Dict[str, Any]) -> bytes:
        """
        Sign data using ElGamal
        Returns signature in a compact format
        """
        # Add timestamp
        data['timestamp'] = int(time.time())
        
        # Convert to canonical JSON string
        data_str = json.dumps(data, sort_keys=True)
        
        # Hash the data
        h = SHA256.new(data_str.encode())
        
        # Sign with ElGamal
        k = int.from_bytes(get_random_bytes(16), 'big') % (self.elgamal_key.p - 1)
        while k == 0:
            k = int.from_bytes(get_random_bytes(16), 'big') % (self.elgamal_key.p - 1)
        
        # Calculate signature components
        r = pow(self.elgamal_key.g, k, self.elgamal_key.p)
        h_int = int.from_bytes(h.digest(), 'big')
        s = ((h_int - self.elgamal_key.x * r) * pow(k, -1, self.elgamal_key.p - 1)) % (self.elgamal_key.p - 1)
        
        # Return signature as bytes
        return json.dumps({'r': str(r), 's': str(s)}).encode()
    
    @staticmethod
    def verify_signature(data: Dict[str, Any], signature: bytes, 
                        pub_key: Dict[str, str]) -> bool:
        """Verify ElGamal signature"""
        # Parse signature
        sig = json.loads(signature.decode())
        r = int(sig['r'])
        s = int(sig['s'])
        
        # Parse public key
        p = int(pub_key['p'])
        g = int(pub_key['g'])
        y = int(pub_key['y'])
        
        # Convert to canonical JSON string
        data_str = json.dumps(data, sort_keys=True)
        
        # Hash the data
        h = SHA256.new(data_str.encode())
        h_int = int.from_bytes(h.digest(), 'big')
        
        # Verify signature
        v1 = pow(y, r, p) * pow(r, s, p) % p
        v2 = pow(g, h_int, p)
        
        return v1 == v2

class SecureMessage:
    """Helper class for creating and parsing secure messages"""
    
    @staticmethod
    def create(data: Dict[str, Any], aes_key: bytes, 
              encrypted_aes_key: bytes, signature: bytes) -> Dict[str, str]:
        """Create a secure message package"""
        # Encrypt the data
        encrypted_data, tag = CryptoManager.encrypt_data(data, aes_key)
        
        # Create message package
        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode(),
            'tag': base64.b64encode(tag).decode(),
            'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
            'signature': base64.b64encode(signature).decode()
        }
    
    @staticmethod
    def parse(message: Dict[str, str]) -> Tuple[bytes, bytes, bytes, bytes]:
        """Parse a secure message package"""
        return (
            base64.b64decode(message['encrypted_data']),
            base64.b64decode(message['tag']),
            base64.b64decode(message['encrypted_key']),
            base64.b64decode(message['signature'])
        )