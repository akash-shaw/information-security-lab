from Crypto.Cipher import DES

key = b'A1B2C3D4'

cipher = DES.new(key, DES.MODE_ECB)

plaintext = b'ConfidentialData'

msg = cipher.encrypt(plaintext)

print(msg)