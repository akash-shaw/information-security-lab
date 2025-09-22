# Hill Cipher 2x2 Encryption (Plain Python)

def hill_encrypt(plaintext, key):
    # Convert letters to numbers A=0..Z=25
    def char_to_num(c):
        return ord(c) - ord('A')
    
    # Convert numbers back to letters
    def num_to_char(n):
        return chr(n + ord('A'))
    
    # Prepare plaintext: remove spaces, uppercase, pad if needed
    text = plaintext.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += 'X'  # filler for odd length
    
    ciphertext = ''
    
    # Encrypt in pairs
    for i in range(0, len(text), 2):
        p1 = char_to_num(text[i])
        p2 = char_to_num(text[i+1])
        
        # Apply Hill cipher formula: C = K * P mod 26
        c1 = (key[0][0]*p1 + key[0][1]*p2) % 26
        c2 = (key[1][0]*p1 + key[1][1]*p2) % 26
        
        ciphertext += num_to_char(c1) + num_to_char(c2)
    
    return ciphertext

# ----------------------------
# Example usage
plaintext = "We live in an insecure world"
key = [[3, 3],
       [2, 7]]

ciphertext = hill_encrypt(plaintext, key)
print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
