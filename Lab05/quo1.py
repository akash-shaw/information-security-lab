def custom_hash(input_string: str) -> int:
    hash_value = 5381
    for char in input_string:
        # Multiply current hash by 33 and add ASCII value of char
        hash_value = ((hash_value * 33) + ord(char))

        # Bitwise mixing example: XOR the hash with a right-shifted version of itself
        hash_value ^= (hash_value >> 16)

    # Keep hash within 32-bit range
    return hash_value & 0xFFFFFFFF


# Example usage:
print(hex(custom_hash("hello")))  # prints hash in hex format
print(hex(custom_hash("world")))
