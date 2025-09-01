from pydoc import plaintext
from binascii import hexlify
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import time

import matplotlib.pyplot as plt

x = [1, 2, 3, 4, 5]
y = [1, 4, 9, 16, 25]

plt.plot(x, y)

plt.xlabel('X-axis')
plt.ylabel('Y-axis')
plt.title('Simple Plot')

plt.show()


def aes_encrypt( plaintext, key):
    if len(key) not in [16, 24, 32]:
        key = key.ljust(16, '0')[:16]

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


def aes_decrypt( encrypted_data, key):
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


def vigenere_encrypt(plaintext, key):
    cipher = ""
    count = 0
    for c in plaintext:
        if c == " ":
            cipher += " "
            continue
        elif c >= 'A' and c <= 'Z':
            cipher_char = chr((ord(c) + ord(key[count]) - 2 * ord('A')) % 26 + ord('A'))
        else:
            cipher_char = chr((ord(c) + ord(key[count]) - 2 * ord('a')) % 26 + ord('a'))
        cipher += cipher_char
        count = (count+1)%len(key)

    return cipher

def vigenere_decrypt(cipher, key):
    plaintext = ""
    count = 0
    for c in cipher:
        if c == " ":
            plaintext += " "
            continue
        elif c >= 'A' and c <= 'Z':
            plaintext_char = chr((ord(c) - ord(key[count])) % 26 + ord('A'))
        else:
            plaintext_char = chr((ord(c) - ord(key[count])) % 26 + ord('a'))
        plaintext += plaintext_char
        count = (count + 1) % len(key)
    return plaintext
while(True):
    print("1. Vigenere cipher")
    print("2. RSA")
    print("3. AES 128")
    print("0. Exit")
    print("Enter Choice: ")
    x = input()
    start_time = time.perf_counter()
    if x=="0":
        break
    elif x=="1":
        key = "POTATO"
        plaintext = "The key is hidden under the mattress"
        cipher = vigenere_encrypt(plaintext, key)
        print("Ciphertext:", cipher)
        dec_plaintext = vigenere_decrypt(cipher,key)
        print("Plaintext:",dec_plaintext)
    elif x=="2":
        key = RSA.generate(1024)
        private_key = key
        public_key = key.publickey()
        print("Keys Generated: ")
        print("Private Key: ", private_key)
        print("Public Key: ", public_key)

        data_to_encrypt = b"The key is hidden under the mattress"
        cipher_rsa = PKCS1_OAEP.new(public_key)

        encrypted = cipher_rsa.encrypt(data_to_encrypt)

        print("Encrypted:", hexlify(encrypted))

        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted = cipher_rsa.decrypt(encrypted)

        print("Decrypted:", decrypted.decode("utf-8"))

    elif x=="3":
        key = b'0123456789ABCDEF'
        # key = input().encode('UTF-8')

        cipher = AES.new(key, AES.MODE_EAX)

        nonce = cipher.nonce
        data = input().encode('utf-8')
        ciphertext = cipher.encrypt_and_digest(data)

        print(ciphertext)
    elif x=="4":
        key = "0123456789ABCDEFGHIJKLMNOP012345"
        text="0123456789ABCDEFGHIJKLMNOP012345"
        print(aes_encrypt(text,key))
        print(aes_decrypt(text,key))

    else:
        print("Invalid Choice")

    time_taken = time.perf_counter() - start_time
    print(f"Time taken: {time_taken:.10f} seconds")


