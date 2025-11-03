from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

def rsa_keygen(bits=2048):
    key = RSA.generate(bits)
    return key

def rsa_en(ptext, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    ctext = cipher.encrypt(ptext.encode('utf-8'))
    return ctext

def rsa_de(ctext, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)
    decrypted = cipher.decrypt(ctext)
    return decrypted.decode('utf-8')

def main():
    print("Welcome to RSA")
    ptext = input("Enter plaintext: ")

    # RSA key pair
    key = rsa_keygen()
    pub_key = key.publickey()
    priv_key = key

    print("\nPublic Key (n, e):")
    print("n =", hex(pub_key.n))
    print("e =", pub_key.e)

    ctext = rsa_en(ptext, pub_key)
    print("\nYour ciphertext (hex):", binascii.hexlify(ctext).decode())

    decrypted = rsa_de(ctext, priv_key)
    print("Your decrypted plaintext:", decrypted)

if __name__ == '__main__':
    main()