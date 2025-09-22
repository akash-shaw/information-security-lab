# Cryptography Lab Tutorial Script
# Author: ChatGPT
# Purpose: Teach essential cryptography concepts and algorithms in Python
# This script includes classical ciphers, RSA, hashing, XOR encryption, and matrix operations

import numpy as np
import hashlib
import random
import base64

########################################
# 1. Helper Functions
########################################

# Function to convert letter to number (A=0, B=1,...)
def letter_to_num(letter):
    return ord(letter.upper()) - ord('A')

# Function to convert number to letter
def num_to_letter(num):
    return chr(num + ord('A'))

# Modular inverse using Extended Euclidean Algorithm
def mod_inverse(a, m):
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x += m0
    return x

########################################
# 2. Classical Ciphers
########################################

# 2.1 Caesar Cipher
def caesar_encrypt(plaintext, key):
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            ciphertext += num_to_letter((letter_to_num(char) + key) % 26)
        else:
            ciphertext += char
    return ciphertext

def caesar_decrypt(ciphertext, key):
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():
            plaintext += num_to_letter((letter_to_num(char) - key) % 26)
        else:
            plaintext += char
    return plaintext

# Example:
print("\n--- Caesar Cipher ---")
text = "HELLO WORLD"
key = 3
encrypted = caesar_encrypt(text, key)
print("Encrypted:", encrypted)
decrypted = caesar_decrypt(encrypted, key)
print("Decrypted:", decrypted)

# 2.2 Vigenère Cipher
def vigenere_encrypt(plaintext, key):
    ciphertext = ''
    key_indices = [letter_to_num(k) for k in key]
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = key_indices[i % len(key)]
            ciphertext += num_to_letter((letter_to_num(char) + shift) % 26)
        else:
            ciphertext += char
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    plaintext = ''
    key_indices = [letter_to_num(k) for k in key]
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = key_indices[i % len(key)]
            plaintext += num_to_letter((letter_to_num(char) - shift) % 26)
        else:
            plaintext += char
    return plaintext

print("\n--- Vigenère Cipher ---")
text = "HELLO WORLD"
key = "KEY"
encrypted = vigenere_encrypt(text, key)
print("Encrypted:", encrypted)
decrypted = vigenere_decrypt(encrypted, key)
print("Decrypted:", decrypted)

# 2.3 Hill Cipher (2x2 matrix)
def hill_encrypt(plaintext, key_matrix):
    plaintext = plaintext.replace(" ", "").upper()
    # Make length even
    if len(plaintext) % 2 != 0:
        plaintext += "X"
    ciphertext = ''
    for i in range(0, len(plaintext), 2):
        pair = np.array([[letter_to_num(plaintext[i])], [letter_to_num(plaintext[i+1])]])
        cipher_pair = np.dot(key_matrix, pair) % 26
        ciphertext += num_to_letter(cipher_pair[0,0])
        ciphertext += num_to_letter(cipher_pair[1,0])
    return ciphertext

# Example Hill key matrix
hill_key = np.array([[3, 3], [2, 5]])
text = "HELLO"
encrypted = hill_encrypt(text, hill_key)
print("\n--- Hill Cipher ---")
print("Encrypted:", encrypted)

########################################
# 3. XOR Encryption (Symmetric Key)
########################################

def xor_encrypt_decrypt(message, key):
    # key can be integer or string
    if isinstance(key, str):
        key = [ord(k) for k in key]
    output = ''
    for i, char in enumerate(message):
        output += chr(ord(char) ^ key[i % len(key)])
    return output

print("\n--- XOR Encryption ---")
message = "HELLO"
key = "KEY"
cipher = xor_encrypt_decrypt(message, key)
print("Encrypted:", cipher)
plain = xor_encrypt_decrypt(cipher, key)
print("Decrypted:", plain)

########################################
# 4. Hashing
########################################

def hash_message(message, algorithm='sha256'):
    if algorithm.lower() == 'md5':
        return hashlib.md5(message.encode()).hexdigest()
    elif algorithm.lower() == 'sha1':
        return hashlib.sha1(message.encode()).hexdigest()
    else:  # default sha256
        return hashlib.sha256(message.encode()).hexdigest()

print("\n--- Hashing ---")
msg = "HELLO"
print("MD5:", hash_message(msg, 'md5'))
print("SHA1:", hash_message(msg, 'sha1'))
print("SHA256:", hash_message(msg))

########################################
# 5. RSA (Basic Implementation)
########################################

# Generate small primes (for lab exam purposes)
p = 17
q = 11
n = p * q
phi = (p - 1) * (q - 1)
e = 7  # choose e such that 1 < e < phi and gcd(e, phi) = 1
d = mod_inverse(e, phi)

def rsa_encrypt(message, e, n):
    return [pow(ord(char), e, n) for char in message]

def rsa_decrypt(cipher, d, n):
    return ''.join([chr(pow(c, d, n)) for c in cipher])

print("\n--- RSA Encryption ---")
message = "HELLO"
cipher = rsa_encrypt(message, e, n)
print("Encrypted:", cipher)
plain = rsa_decrypt(cipher, d, n)
print("Decrypted:", plain)

########################################
# 6. Base64 Encoding/Decoding
########################################

msg = "HELLO"
encoded = base64.b64encode(msg.encode())
decoded = base64.b64decode(encoded).decode()
print("\n--- Base64 Encoding ---")
print("Encoded:", encoded)
print("Decoded:", decoded)

########################################
# 7. Frequency Analysis (Optional for Substitution Ciphers)
########################################

def frequency_analysis(text):
    freq = {}
    for char in text.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
    return freq

text = "HELLO WORLD"
freq = frequency_analysis(text)
print("\n--- Frequency Analysis ---")
print(freq)

########################################
# 8. Summary
########################################

print("\nCryptography Lab concepts covered:")
print("- Classical Ciphers: Caesar, Vigenère, Hill")
print("- Symmetric Encryption: XOR")
print("- Hash Functions: MD5, SHA1, SHA256")
print("- Asymmetric Encryption: Basic RSA")
print("- Encoding/Decoding: Base64")
print("- Frequency Analysis for cryptanalysis")
