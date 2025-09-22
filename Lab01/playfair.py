
def generate_matrix(key):
    key = key.upper().replace("J", "I")  # I/J treated same
    matrix = []
    used = set()

    # Add key letters
    for ch in key:
        if ch not in used and ch.isalpha():
            matrix.append(ch)
            used.add(ch)

    # Add rest of alphabet
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  # J excluded
        if ch not in used:
            matrix.append(ch)
            used.add(ch)

    # Convert to 5x5
    return [matrix[i:i+5] for i in range(0, 25, 5)]


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

        if a == b:  # no same letters in pair
            pairs.append(a + 'X')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs


def find_position(matrix, ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j
    return None


def encrypt_pair(pair, matrix):
    a, b = pair[0], pair[1]
    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    # Rule 1: Same row
    if r1 == r2:
        return matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
    # Rule 2: Same column
    elif c1 == c2:
        return matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
    # Rule 3: Rectangle
    else:
        return matrix[r1][c2] + matrix[r2][c1]


def playfair_encrypt(plaintext, key):
    matrix = generate_matrix(key)
    pairs = format_plaintext(plaintext)
    ciphertext = ""

    for p in pairs:
        ciphertext += encrypt_pair(p, matrix)

    return ciphertext, matrix


# ----------------------------
# Example usage
plaintext = "The key is hidden under the door pad"
key = "GUIDANCE"

ciphertext, matrix = playfair_encrypt(plaintext, key)

print("5x5 Matrix:")
for row in matrix:
    print(row)

print("\nPlaintext:", plaintext)
print("Ciphertext:", ciphertext)


