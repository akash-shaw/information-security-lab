# Brute-force attack on additive (shift/Caesar) cipher

def decrypt_additive(ciphertext, key):
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():  # only decrypt letters
            num = ord(c.upper()) - ord('A')
            plain_num = (num - key) % 26
            plaintext += chr(plain_num + ord('A'))
        else:
            plaintext += c  # keep symbols as is
    return plaintext

# ----------------------------
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Assume key is around birthday 13 (try 8 to 18)
for key in range(8, 19):
    plaintext = decrypt_additive(ciphertext, key)
    print(f"Key = {key}: {plaintext}")
