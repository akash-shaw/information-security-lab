from Crypto.Cipher import AES

key = b'0123456789ABCDEF'

cipher = AES.new(key, AES.MODE_EAX)


nonce = cipher.nonce
data = b'SensitiveInformation'
ciphertext= cipher.encrypt_and_digest(data)

print(ciphertext)