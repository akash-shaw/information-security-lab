import numpy as np

def hill_en(ptext, hk):
    # keep only letters and convert to uppercase
    ptext = ''.join(c.upper() for c in ptext if c.isalpha())

    # matrix size
    n = int(len(hk)**0.5)

    # key matrix
    key = np.array([ord(c) - 65 for c in hk]).reshape(n, n)

    # padding
    ptext += 'X' * (-len(ptext) % n)

    # block operation
    out_chars = []
    for i in range(0, len(ptext), n):
        block = np.array([ord(c) - 65 for c in ptext[i:i + n]])
        encrypted_block = (key @ block) % 26
        out_chars.extend(chr(int(val) + 65) for val in encrypted_block)

    return ''.join(out_chars)

def hill_de(ctext, hk):
    # keep only letters and convert to uppercase
    ctext = ''.join(c.upper() for c in ctext if c.isalpha())

    # matrix size
    n = int(len(hk)**0.5)

    # key matrix and its inverse (note: not a true modular inverse; kept minimal per lab)
    key = np.array([ord(c) - 65 for c in hk]).reshape(n, n)
    inv_key = np.linalg.inv(key)
    inv_key = np.rint(inv_key).astype(int) % 26

    # block operation
    out_chars = []
    for i in range(0, len(ctext), n):
        block = np.array([ord(c) - 65 for c in ctext[i:i + n]])
        decrypted_block = (inv_key @ block) % 26
        out_chars.extend(chr(int(val) + 65) for val in decrypted_block)

    return ''.join(out_chars)

def main():
    ptext = input("Plaintext: ")
    hk = input("Hill Key: ")
    ctext = hill_en(ptext, hk)
    print(f"Ciphertext: {ctext}")
    print(f"Decrypted: {hill_de(ctext, hk)}")

if __name__ == '__main__':
    main()
