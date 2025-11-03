from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_cipher(key):
    return AES.new(key.encode('utf-8'), AES.MODE_ECB)

def aes_en(ptext, key):
    cipher = aes_cipher(key)
    ptext = pad(ptext.encode('utf-8'), AES.block_size)
    return cipher.encrypt(ptext)

def aes_de(ctext, key):
    cipher = aes_cipher(key)
    decrypted = cipher.decrypt(ctext)
    return unpad(decrypted, AES.block_size).decode('utf-8')

def aespad_key(key):
    return key.ljust(16)[:16]

    # 16 for 128 bit, 24 for 192, 32 for 256

def main():
    print("Welcome to AES-128")
    ptext = input("Enter plaintext: ")
    key = input("Enter key: ")

    key = aespad_key(key)

    ctext = aes_en(ptext, key)
    print("Your ciphertext: ", ctext)
    print("Your decrypted plaintext: ", aes_de(ctext, key))

if __name__ == '__main__':
    main()