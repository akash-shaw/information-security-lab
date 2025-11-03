## ptext = plaintext
## ctext = ciphertext
## mk = multiplicative key
## ak = additive key

def add_cipher_en(ptext, ak):
    result = ""
    for ch in ptext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr((ord(ch) - base + ak) % 26 + base)
        else:
            result += ch
    return result

def add_cipher_de(ctext, ak):
    result = ""
    for ch in ctext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr((ord(ch) - base - ak) % 26 + base)
        else:
            result += ch
    return result

def mult_cipher_en(ptext, mk):
    result = ""
    for ch in ptext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - base
            result += chr((x * mk) % 26 + base)
        else:
            result += ch
    return result

def mult_cipher_de(ctext, mk):
    result = ""
    inverse = pow(mk, -1, 26)
    for ch in ctext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - base
            result += chr((x * inverse) % 26 + base)
        else:
            result += ch
    return result

def affine_en(ptext, ak, mk):
    result = ""
    for ch in ptext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - base
            result += chr(((x * mk + ak) % 26) + base)
        else:
            result += ch
    return result

def affine_de(ctext, ak, mk):
    result = ""
    inverse = pow(mk, -1, 26)
    for ch in ctext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - base
            result += chr((((x - ak) * inverse) % 26) + base)
        else:
            result += ch
    return result

def mult_inverse(mk):
    inverse = pow(mk, -1, 26)
    return inverse

def operator(argument,ptext,ak,mk):
    match argument:
        case '1':
            print("Additive Cipher")
            print("Plaintext: ", ptext)
            print("Additive Key: ", ak)
            ctext = add_cipher_en(ptext, ak)
            print("Ciphertext: ", ctext)
            print("Decrypted Text: ", add_cipher_de(ctext, ak))
        case '2':
            print("Multiplicative Cipher")
            print("Plaintext: ", ptext)
            print("Multiplicative Key: ", mk)
            ctext = mult_cipher_en(ptext, mk)
            print("Ciphertext: ", ctext)
            print("Multiplicative Inverse: ", mult_inverse(mk))
            print("Decrypted Text: ", mult_cipher_de(ctext, mk))
        case '3':
            print("Affine Cipher")
            print("Plaintext: ", ptext)
            print("Additive Key: ", ak)
            print("Multiplicative Key: ", mk)
            ctext = affine_en(ptext, ak, mk)
            print("Ciphertext: ", ctext)
            print("Affine Inverse: ", mult_inverse(mk))
            print("Decrypted Text: ", affine_de(ctext, ak, mk))
        case '4':
            print("Goodbye")
            exit()
        case _:
            print("Invalid Choice, please try again.")

def main():
    ptext = input("Kindly enter your desired plaintext: ")
    ak = 20
    mk = 15

    print("Welcome to the substitution cipher system.")
    print("Enter your choice of algorithm")
    print("1. Additive Cipher")
    print("2. Multiplicative Cipher")
    print("3. Affine Cipher")
    print("4. Exit")

    while True:
        op = input("Enter your choice of operation: ")
        operator(op, ptext, ak, mk)

if __name__ == '__main__':
    main()
