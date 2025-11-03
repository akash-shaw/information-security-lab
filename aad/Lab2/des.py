from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def des_cipher(key):
    return DES.new(key.encode('utf-8'), DES.MODE_ECB)

def des_en(ptext, key):
    cipher = des_cipher(key)
    padded_text = pad(ptext.encode('utf-8'), DES.block_size)
    return cipher.encrypt(padded_text)

def des_de(ctext, key):
    cipher = des_cipher(key)
    decrypted = unpad(cipher.decrypt(ctext), DES.block_size)
    return decrypted.decode('utf-8')

def despad_key(key):
    return key.ljust(8)[:8]

def main():
    print("Welcome to DES (Original)")
    ptext = input("Enter plaintext: ")
    key = input("Enter key: ")
    key = despad_key(key)
    ctext = des_en(ptext, key)
    print("Your ciphertext: ", ctext)
    print("Your decrypted plaintext: ", des_de(ctext, key))

if __name__ == '__main__':
    main()