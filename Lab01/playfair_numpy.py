import numpy as np

def generate_matrix(key):
    key = key.upper().replace("J", "I")
    used = []
    
    # Add key letters
    for ch in key:
        if ch.isalpha() and ch not in used:
            used.append(ch)
    
    # Add rest of alphabet (J excluded)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in used:
            used.append(ch)
    
    return np.array(used).reshape(5, 5)


def format_plaintext(text):
    text = text.upper().replace("J", "I").replace(" ", "")
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        b = ''
        if i + 1 < len(text):
            b = text[i+1]
        else:
            b = 'X'   # filler if odd length

        if a == b:  # same letter case
            pairs.append(a + 'X')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def find_position(matrix, ch):
    pos = np.argwhere(matrix == ch)[0]
    return pos[0], pos[1]


def encrypt_pair(pair, matrix):
    a, b = pair[0], pair[1]
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    # Rule 1: Same row
    if r1 == r2:
        return matrix[r1, (c1+1)%5] + matrix[r2, (c2+1)%5]
    # Rule 2: Same column
    elif c1 == c2:
        return matrix[(r1+1)%5, c1] + matrix[(r2+1)%5, c2]
    # Rule 3: Rectangle
    else:
        return matrix[r1, c2] + matrix[r2, c1]


def decrypt_pair(pair, matrix):
    a, b = pair[0], pair[1]
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    # Rule 1: Same row
    if r1 == r2:
        return matrix[r1, (c1-1)%5] + matrix[r2, (c2-1)%5]
    # Rule 2: Same column
    elif c1 == c2:
        return matrix[(r1-1)%5, c1] + matrix[(r2-1)%5, c2]
    # Rule 3: Rectangle
    else:
        return matrix[r1, c2] + matrix[r2, c1]


def playfair_encrypt(plaintext, key):
    matrix = generate_matrix(key)
    pairs = format_plaintext(plaintext)
    ciphertext = "".join([encrypt_pair(p, matrix) for p in pairs])
    return ciphertext, matrix


def playfair_decrypt(ciphertext, key):
    matrix = generate_matrix(key)
    pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    plaintext = "".join([decrypt_pair(p, matrix) for p in pairs])
    return plaintext


# ----------------------------
# Example usage
plaintext = "The key is hidden under the door pad"
key = "GUIDANCE"

ciphertext, matrix = playfair_encrypt(plaintext, key)

print("5x5 Matrix:")
print(matrix)

print("\nPlaintext:", plaintext)
print("Ciphertext:", ciphertext)

decrypted = playfair_decrypt(ciphertext, key)
print("Decrypted (raw):", decrypted)
