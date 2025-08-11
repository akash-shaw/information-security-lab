from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify

key = RSA.generate(1024)
private_key = key
public_key = key.publickey()

data_to_encrypt = b"I got a brand new saxophone."
cipher_rsa = PKCS1_OAEP.new(public_key)

encrypted = cipher_rsa.encrypt(data_to_encrypt)

print("Encrypted:", hexlify(encrypted))

cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted = cipher_rsa.decrypt(encrypted)

print("Decrypted:", decrypted.decode("utf-8"))