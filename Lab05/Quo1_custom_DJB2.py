def custom_hash(input_string):
    # Initial hash value
    hash_value = 5381
    
    for char in input_string:
        # Multiply current hash by 33 and add ASCII value of character
        hash_value = ((hash_value * 33) + ord(char)) & 0xFFFFFFFF  # 32-bit mask
    
    return hash_value

# Example usage
text = "Hello, World!"
hashed_value = custom_hash(text)
print(f"Hash of '{text}': {hashed_value}")
