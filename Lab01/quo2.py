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

def generate_autokey(plaintext, key):
    plaintext = plaintext.replace(" ", "")
    for i in range(len(plaintext)-len(key)):
        key += plaintext[i]
    return key

def autokey_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "")
    autokey = generate_autokey(plaintext, key)
    return  vigenere_encrypt(plaintext, autokey)

def autokey_decrypt(plaintext, autokey):
    return  vigenere_decrypt(plaintext, autokey)

text = "the house is being sold tonight"
mykey = "n"
output = autokey_encrypt(text, mykey)
pt = autokey_decrypt(output, generate_autokey(text, mykey))
print(output)
print(pt)
