"""
Question 1: Playfair Cipher Implementation
A straightforward cipher implementation using Playfair algorithm
"""

def create_playfair_matrix(key):
    """Create 5x5 Playfair matrix from key"""
    # Remove duplicates and convert to uppercase
    key = ''.join(dict.fromkeys(key.upper().replace('J', 'I')))
    
    # Create alphabet without J (I and J share same position)
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    
    # Add remaining letters
    for char in alphabet:
        if char not in key:
            key += char
    
    # Create 5x5 matrix
    matrix = []
    for i in range(5):
        row = []
        for j in range(5):
            row.append(key[i * 5 + j])
        matrix.append(row)
    
    return matrix

def find_position(matrix, char):
    """Find position of character in matrix"""
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return None

def prepare_text(text):
    """Prepare text for Playfair encryption"""
    text = text.upper().replace('J', 'I').replace(' ', '')
    
    # Add X between duplicate letters and make even length
    prepared = ''
    i = 0
    while i < len(text):
        prepared += text[i]
        if i + 1 < len(text):
            if text[i] == text[i + 1]:
                prepared += 'X'
            else:
                prepared += text[i + 1]
                i += 1
        else:
            prepared += 'X'
        i += 1
    
    return prepared

def playfair_encrypt(plaintext, key):
    """Encrypt text using Playfair cipher"""
    matrix = create_playfair_matrix(key)
    text = prepare_text(plaintext)
    
    encrypted = ''
    for i in range(0, len(text), 2):
        char1, char2 = text[i], text[i + 1]
        row1, col1 = find_position(matrix, char1)
        row2, col2 = find_position(matrix, char2)
        
        if row1 == row2:  # Same row
            encrypted += matrix[row1][(col1 + 1) % 5]
            encrypted += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Same column
            encrypted += matrix[(row1 + 1) % 5][col1]
            encrypted += matrix[(row2 + 1) % 5][col2]
        else:  # Rectangle
            encrypted += matrix[row1][col2]
            encrypted += matrix[row2][col1]
    
    return encrypted

def playfair_decrypt(ciphertext, key):
    """Decrypt text using Playfair cipher"""
    matrix = create_playfair_matrix(key)
    
    decrypted = ''
    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i + 1]
        row1, col1 = find_position(matrix, char1)
        row2, col2 = find_position(matrix, char2)
        
        if row1 == row2:  # Same row
            decrypted += matrix[row1][(col1 - 1) % 5]
            decrypted += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:  # Same column
            decrypted += matrix[(row1 - 1) % 5][col1]
            decrypted += matrix[(row2 - 1) % 5][col2]
        else:  # Rectangle
            decrypted += matrix[row1][col2]
            decrypted += matrix[row2][col1]
    
    return decrypted

# Example usage
if __name__ == "__main__":
    key = "MONARCHY"
    plaintext = "INSTRUMENTS"
    
    print("Playfair Cipher Implementation")
    print("=" * 40)
    print(f"Key: {key}")
    print(f"Plaintext: {plaintext}")
    
    # Create and display matrix
    matrix = create_playfair_matrix(key)
    print("\nPlayfair Matrix:")
    for row in matrix:
        print(' '.join(row))
    
    # Encrypt
    encrypted = playfair_encrypt(plaintext, key)
    print(f"\nEncrypted: {encrypted}")
    
    # Decrypt
    decrypted = playfair_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted}")
