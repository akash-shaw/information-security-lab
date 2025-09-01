# Fixed 5x5 Playfair matrix
playfair_matrix = [
    ['G', 'U', 'I', 'D', 'A'],
    ['N', 'C', 'E', 'B', 'F'],
    ['H', 'K', 'L', 'M', 'O'],
    ['P', 'Q', 'R', 'S', 'T'],
    ['V', 'W', 'X', 'Y', 'Z']
]

# Helper function to find the position of a character in the matrix
def find_position(char, matrix):
    """Find the row and column of a character in the matrix."""
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return None

# Preprocessing function to prepare text for Playfair cipher
def preprocess_text(text):
    """Preprocess the text for Playfair cipher: remove spaces, handle repeated letters, and make pairs."""
    text = text.upper().replace(" ", "").replace("J", "I")  # Convert to uppercase and handle 'J'
    processed_text = ""
    i = 0
    while i < len(text):
        processed_text += text[i]
        if i + 1 < len(text) and text[i] == text[i + 1]:
            processed_text += 'X'  # Insert 'X' between repeated characters
        elif i + 1 < len(text):
            processed_text += text[i + 1]
        else:
            processed_text += 'X'  # Append 'X' if odd length
        i += 2
    return processed_text

# Encryption function
def playfair_encrypt(plaintext, matrix):
    """Encrypt the given plaintext using Playfair cipher rules."""
    plaintext = preprocess_text(plaintext)
    ciphertext = ""

    # Process each pair of letters
    for i in range(0, len(plaintext), 2):
        row1, col1 = find_position(plaintext[i], matrix)
        row2, col2 = find_position(plaintext[i + 1], matrix)

        # Rule 1: Same row, move right
        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]

        # Rule 2: Same column, move down
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]

        # Rule 3: Rectangle rule, swap columns
        else:
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]

    return ciphertext

# Decryption function
def playfair_decrypt(ciphertext, matrix):
    """Decrypt the given ciphertext using Playfair cipher rules."""
    plaintext = ""

    # Process each pair of letters
    for i in range(0, len(ciphertext), 2):
        row1, col1 = find_position(ciphertext[i], matrix)
        row2, col2 = find_position(ciphertext[i + 1], matrix)

        # Rule 1: Same row, move left
        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5]
            plaintext += matrix[row2][(col2 - 1) % 5]

        # Rule 2: Same column, move up
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1]
            plaintext += matrix[(row2 - 1) % 5][col2]

        # Rule 3: Rectangle rule, swap columns
        else:
            plaintext += matrix[row1][col2]
            plaintext += matrix[row2][col1]

    return plaintext

# Example usage
plaintext = "the key is hidden under the doorpad"
print(f"Original Plaintext: {plaintext}")

# Encrypt the plaintext
encrypted_text = playfair_encrypt(plaintext, playfair_matrix)
print(f"Encrypted Text: {encrypted_text}")

# Decrypt the encrypted text
decrypted_text = playfair_decrypt(encrypted_text, playfair_matrix)
print(f"Decrypted Text: {decrypted_text}")
