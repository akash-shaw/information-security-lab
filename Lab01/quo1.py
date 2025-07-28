def additive_cipher_encrypt(key, plaintext):
    cipher = ""
    for c in plaintext:
        if c==" ":
            cipher_char = " "
        elif c>='A' and c<='Z' :
            cipher_char = chr( ( ord(c) - ord('A') + key)%26 + ord('A'))
        else:
            cipher_char = chr( ( ord(c) - ord('a') + key) % 26 + ord('a'))
        cipher += cipher_char

    return  cipher

def additive_cipher_decrypt(key, cipher):
    plaintext = ""
    for c in cipher:
        if c == " ":
            plaintext_char = " "
        elif c>='A' and c<='Z' :
            plaintext_char = chr( ( ord(c) - ord('A') - key)%26 + ord('A'))
        else:
            plaintext_char = chr( ( ord(c) - ord('a') - key) % 26 + ord('a'))

        plaintext += plaintext_char

    return  plaintext

def multiplicative_cipher_encrypt(key, plaintext):
    cipher = ""
    for c in plaintext:
        if c == " ":
            cipher_char = " "
        elif c >= 'A' and c <= 'Z':
            cipher_char = chr( ((ord(c) - ord('A')) * key) % 26 + ord('A'))
        else:
            cipher_char = chr( ((ord(c) - ord('a')) * key) % 26 + ord('a'))

        cipher += cipher_char

    return cipher

def find_inverse(key):
    for i in range(1,26):
        if (key*i)%26 == 1:
            return i
    return -1

def multiplicative_cipher_decrypt(key, cipher):
    key_inverse = find_inverse(key)
    if key_inverse==-1 :
        return "INVALID KEY"
    plaintext = ""
    for c in cipher:
        if c == " ":
            plaintext_char = " "
        elif c >= 'A' and c <= 'Z':
            plaintext_char = chr( ((ord(c) - ord('A')) * key_inverse) % 26 + ord('A'))
        else:
            plaintext_char = chr( ((ord(c) - ord('a')) * key_inverse) % 26 + ord('a'))

        plaintext += plaintext_char

    return plaintext

def affine_cipher_encrypt(key_a, key_b, plaintext):
    cipher = ""
    for c in plaintext:
        if c == " ":
            cipher_char = " "
        elif c >= 'A' and c <= 'Z':
            cipher_char = chr(( (ord(c) - ord('A')) * key_a + key_b ) % 26 + ord('A'))
        else:
            cipher_char = chr(( (ord(c) - ord('a')) * key_a + key_b ) % 26 + ord('a'))

        cipher += cipher_char

    return cipher

def affine_cipher_decrypt(key_a, key_b, cipher):
    key_a_inverse = find_inverse(key_a)
    if key_a_inverse==-1 :
        return "INVALID KEY"
    plaintext = ""
    for c in cipher:
        if c == " ":
            plaintext_char = " "
        elif c >= 'A' and c <= 'Z':
            plaintext_char = chr( ( key_a_inverse * ( ord(c) - ord('A') - key_b )  % 26 ) + ord('A') )
        else:
            # plaintext_char = chr( ((ord(c) - ord('a')) * key_inverse) % 26 + ord('a'))
            plaintext_char = chr( ( key_a_inverse * ( ord(c) - ord('a') - key_b )  % 26 ) + ord('a') )
        plaintext += plaintext_char

    return plaintext

text = "I am learning information security"

print( affine_cipher_decrypt(15, 20, affine_cipher_encrypt(15, 20, text) ) )
