# Affine cipher decryption

def modinv(a, m):
    """Modular inverse of a under modulo m"""
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def affine_decrypt(ciphertext, a, b):
    m = 26
    a_inv = modinv(a, m)
    if a_inv is None:
        raise ValueError("a has no modular inverse modulo 26")
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            y = ord(c.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('a'))  # lowercase
        else:
            plaintext += c
    return plaintext

# ----------------------------
# Ciphertext
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

# Known plaintext "ab" -> "GL" gives key a=5, b=6
a, b = 5, 6

# Decrypt
plaintext = affine_decrypt(ciphertext, a, b)
print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)
