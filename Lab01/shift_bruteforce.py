# Known Plaintext Attack on Shift Cipher

def find_shift(plaintext, ciphertext):
    """
    Find the shift key using a known plaintext-ciphertext pair.
    Both inputs should be the same length and uppercase.
    """
    p_num = [ord(c) - ord('A') for c in plaintext.upper()]
    c_num = [ord(c) - ord('A') for c in ciphertext.upper()]
    # Shift is (C - P) mod 26
    shift = (c_num[0] - p_num[0]) % 26  # assume uniform shift
    return shift

def decrypt_shift(ciphertext, shift):
    """
    Decrypt ciphertext using given shift key.
    """
    c_num = [ord(c) - ord('A') for c in ciphertext.upper()]
    p_num = [(n - shift) % 26 for n in c_num]
    plaintext = ''.join([chr(n + ord('A')) for n in p_num])
    return plaintext

# ----------------------------
# Example usage

# Known plaintext attack
known_plain = "YES"
known_cipher = "CIW"

# Ciphertext to decrypt
ciphertext_to_decrypt = "XVIEWYWI"

# Step 1: Find the shift
shift = find_shift(known_plain, known_cipher)
print("Shift key found:", shift)

# Step 2: Decrypt new ciphertext
plaintext = decrypt_shift(ciphertext_to_decrypt, shift)
print("Ciphertext:", ciphertext_to_decrypt)
print("Plaintext:", plaintext)
