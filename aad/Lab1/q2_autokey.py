def vigenere_en(ptext, vk):
    result = []
    ptext = ptext.upper()
    vk = vk.upper()
    kl = len(vk)
    for i, ch in enumerate(ptext):
        if ch.isalpha():
            shift = (ord(vk[i % kl]) - ord('A')) % 26
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


def vigenere_de(ctext, vk):
    result = []
    ctext = ctext.upper()
    vk = vk.upper()
    kl = len(vk)
    for i, ch in enumerate(ctext):
        if ch.isalpha():
            shift = (ord(vk[i % kl]) - ord('A')) % 26
            result.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)

def autokey_en(ptext, ak):
    k = ord(ak.upper()) if isinstance(ak, str) else ak
    out = []
    for ch in ptext.upper():
        if ch.isalpha():
            out_ch = chr((ord(ch) - 65 + (k - 65)) % 26 + 65)
            out.append(out_ch); k = ord(ch)
        else:
            out.append(ch)
    return ''.join(out)

def autokey_de(ctext, ak):
    k = ord(ak.upper()) if isinstance(ak, str) else ak
    out = []
    for ch in ctext.upper():
        if ch.isalpha():
            p = chr((ord(ch) - 65 - (k - 65)) % 26 + 65)
            out.append(p); k = ord(p)
        else:
            out.append(ch)
    return ''.join(out)

def operator(argument,ptext,ak,vk):
    match argument:
        case '1':
            print("Vigenere Cipher")
            print("Plaintext: ", ptext)
            print("Vigenere Key: ", vk)
            ctext = vigenere_en(ptext, vk)
            print("Ciphertext: ", ctext)
            print("Decrypted Text: ", vigenere_de(ctext, vk))
        case '2':
            print("Autokey Cipher")
            print("Plaintext: ", ptext)
            print("Auto Key: ", ak)
            ctext = autokey_en(ptext, ak)
            print("Ciphertext: ", ctext)
            print("Decrypted Text: ", autokey_de(ctext, ak))
        case '3':
            print("Goodbye")
            exit()
        case _:
            print("Invalid Choice, please try again.")

def main():
    ptext = input("Kindly enter your desired plaintext: ")
    vk = input("Kindly enter the Vigenere Key: ")
    ak = int(input("Kindly enter the Autokey: "))

    print("Welcome to the Autokey cipher system.")
    print("Enter your choice of algorithm")
    print("1. Vigenere Cipher")
    print("2. Autokey Cipher")
    print("3. Exit")

    while True:
        op = input("Enter your choice of operation: ")
        operator(op, ptext, ak, vk)


if __name__ == '__main__':
    main()
