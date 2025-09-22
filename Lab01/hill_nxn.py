import numpy as np

def text_to_numbers(text):
    text = text.upper().replace(" ", "")
    return [ord(c) - ord('A') for c in text]

def numbers_to_text(nums):
    return ''.join([chr(n % 26 + ord('A')) for n in nums])

def pad_text(text, n):
    if len(text) % n != 0:
        text += 'X' * (n - len(text) % n)
    return text

def hill_encrypt(text, key):
    n = key.shape[0]
    text = pad_text(text.upper().replace(" ", ""), n)
    nums = text_to_numbers(text)
    
    ciphertext = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i:i+n])
        cipher_block = key.dot(block) % 26
        ciphertext.extend(cipher_block)
    
    return numbers_to_text(ciphertext)

# ----------------------------
# User input

plaintext = input("Enter plaintext: ")

n = int(input("Enter key size (n for n x n): "))
print(f"Enter {n*n} key values row by row (space separated):")
key_values = list(map(int, input().split()))
if len(key_values) != n*n:
    raise ValueError("Number of key values does not match n x n.")

key_matrix = np.array(key_values).reshape(n, n)

# Encrypt
ciphertext = hill_encrypt(plaintext, key_matrix)
print("\nPlaintext:", plaintext)
print("Ciphertext:", ciphertext)
