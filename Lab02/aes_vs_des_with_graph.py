from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time
import matplotlib.pyplot as plt

# ----------------------------
# Message
message = "Performance Testing of Encryption Algorithms"
data = message.encode()

# DES setup
des_key = b"8ByteKey"  # 8 bytes for DES
des_block_size = 8
des_data = pad(data, des_block_size)
des_cipher = DES.new(des_key, DES.MODE_ECB)

# AES-256 setup
aes_key = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes = 256 bits
aes_block_size = 16
aes_data = pad(data, aes_block_size)
aes_cipher = AES.new(aes_key, AES.MODE_ECB)

# ----------------------------
# DES timing
start = time.time()
des_ciphertext = des_cipher.encrypt(des_data)
des_encrypt_time = time.time() - start

start = time.time()
des_decrypted = unpad(des_cipher.decrypt(des_ciphertext), des_block_size)
des_decrypt_time = time.time() - start

# ----------------------------
# AES-256 timing
start = time.time()
aes_ciphertext = aes_cipher.encrypt(aes_data)
aes_encrypt_time = time.time() - start

start = time.time()
aes_decrypted = unpad(aes_cipher.decrypt(aes_ciphertext), aes_block_size)
aes_decrypt_time = time.time() - start

# ----------------------------
# Print times
print(f"DES encryption time: {des_encrypt_time*1000:.4f} ms")
print(f"DES decryption time: {des_decrypt_time*1000:.4f} ms")
print(f"AES-256 encryption time: {aes_encrypt_time*1000:.4f} ms")
print(f"AES-256 decryption time: {aes_decrypt_time*1000:.4f} ms")

# ----------------------------
# Plotting
labels = ['DES', 'AES-256']
encrypt_times = [des_encrypt_time*1000, aes_encrypt_time*1000]
decrypt_times = [des_decrypt_time*1000, aes_decrypt_time*1000]

x = range(len(labels))
plt.bar(x, encrypt_times, width=0.4, label='Encryption', align='center')
plt.bar([i + 0.4 for i in x], decrypt_times, width=0.4, label='Decryption', align='center')

plt.xticks([i + 0.2 for i in x], labels)
plt.ylabel('Time (ms)')
plt.title('DES vs AES-256 Encryption/Decryption Time')
plt.legend()
plt.show()
