from crypto.Cipher import DES, AES
from crypto.Util.Padding import pad, unpad
from crypto.Random import get_random_bytes
import time
import matplotlib.pyplot as plt

# ----------------------------
# Messages to encrypt
messages = [
    "Message One for testing",
    "Message Two for encryption",
    "Message Three AES DES",
    "Fourth message example",
    "Fifth secret text"
]

# DES key (8 bytes)
des_key = b"8ByteKey"

# AES keys
aes_keys = {
    "AES-128": b"0123456789ABCDEF",            # 16 bytes
    "AES-192": b"0123456789ABCDEF01234567",    # 24 bytes
    "AES-256": b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes
}

# Modes of operation to test
modes = ["ECB", "CBC", "CFB"]

# Function to create cipher based on mode
def create_cipher(algorithm, key, mode):
    if algorithm == "DES":
        if mode == "ECB":
            return DES.new(key, DES.MODE_ECB)
        elif mode == "CBC":
            return DES.new(key, DES.MODE_CBC, get_random_bytes(8))
        elif mode == "CFB":
            return DES.new(key, DES.MODE_CFB, get_random_bytes(8))
    else:  # AES
        if mode == "ECB":
            return AES.new(key, AES.MODE_ECB)
        elif mode == "CBC":
            return AES.new(key, AES.MODE_CBC, get_random_bytes(16))
        elif mode == "CFB":
            return AES.new(key, AES.MODE_CFB, get_random_bytes(16))

# Store times
times = {}

# ----------------------------
# Encryption/Decryption and timing
for algo in ["DES", "AES-128", "AES-192", "AES-256"]:
    times[algo] = {}
    for mode in modes:
        encrypt_time = 0
        decrypt_time = 0
        for msg in messages:
            data = msg.encode()
            # Pad for block cipher (ECB and CBC only)
            if algo.startswith("AES"):
                block_size = 16
            else:
                block_size = 8

            if mode in ["ECB", "CBC"]:
                data_pad = pad(data, block_size)
            else:
                data_pad = data

            key = des_key if algo == "DES" else aes_keys[algo]

            # Create cipher
            cipher = create_cipher(algo if algo=="DES" else "AES", key, mode)

            # Encrypt
            start = time.time()
            ciphertext = cipher.encrypt(data_pad)
            encrypt_time += (time.time() - start)

            # Decrypt
            # For ECB/CBC, need new cipher instance with same key and IV
            if mode in ["CBC", "CFB"]:
                iv = cipher.iv
                cipher_dec = create_cipher(algo if algo=="DES" else "AES", key, mode)
                if hasattr(cipher_dec, "iv"):
                    cipher_dec.iv = iv
            else:
                cipher_dec = create_cipher(algo if algo=="DES" else "AES", key, mode)

            start = time.time()
            decrypted = cipher_dec.decrypt(ciphertext)
            if mode in ["ECB", "CBC"]:
                decrypted = unpad(decrypted, block_size)
            decrypt_time += (time.time() - start)

        # Average over 5 messages
        times[algo][mode] = {
            "encrypt": encrypt_time / len(messages) * 1000,  # in ms
            "decrypt": decrypt_time / len(messages) * 1000
        }

# ----------------------------
# Plotting
import numpy as np

x = np.arange(len(modes))
width = 0.2

fig, ax = plt.subplots(figsize=(10,6))

for i, algo in enumerate(times.keys()):
    encrypt_times = [times[algo][m]["encrypt"] for m in modes]
    decrypt_times = [times[algo][m]["decrypt"] for m in modes]
    ax.bar(x + i*width, encrypt_times, width, label=f"{algo} Encrypt")

ax.set_xticks(x + 1.5*width)
ax.set_xticklabels(modes)
ax.set_ylabel("Average Encryption Time (ms)")
ax.set_title("Encryption Time for DES and AES with Different Modes")
ax.legend()
plt.show()

# Similar plot can be made for decryption if needed
