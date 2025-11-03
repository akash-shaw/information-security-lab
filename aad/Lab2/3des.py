from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

def des3_cipher(key):
    return DES3.new(key.encode('utf-8'), DES3.MODE_ECB)

def des3_en(ptext, key):
    cipher = des3_cipher(key)
    padded_text = pad(ptext.encode('utf-8'), DES3.block_size)
    return cipher.encrypt(padded_text)

def des3_de(ctext, key):
    cipher = des3_cipher(key)
    decrypted = unpad(cipher.decrypt(ctext), DES3.block_size)
    return decrypted.decode('utf-8')

def despad_key(key):
    key = key.ljust(24)[:24]
    return key

def main():
    print("Welcome to 3DES (Triple DES)")
    ptext = input("Enter plaintext: ")
    key = input("Enter key (minimum 16 characters for 3DES): ")
    key = despad_key(key)
    ctext = des3_en(ptext, key)
    print("Your ciphertext: ", ctext)
    print("Your decrypted plaintext: ", des3_de(ctext, key))

if __name__ == '__main__':
    main()