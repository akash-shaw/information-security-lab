import random
from math import gcd, lcm
from sympy import isprime, randprime


def generate_prime(bits=512):
    # Use sympy's randprime for efficiency
    return randprime(2 ** (bits - 1), 2**bits)


def generate_keypair(bits=512):
    p = generate_prime(bits)
    q = generate_prime(bits)

    n = p * q
    n_squared = n * n
    lambda_n = lcm(p - 1, q - 1)

    g = n + 1

    def L(x):
        return (x - 1) // n

    # Convert to int to avoid sympy Integer type issues
    mu = pow(int(L(pow(g, int(lambda_n), n_squared))), -1, n)

    public_key = (n, g)
    private_key = (int(lambda_n), mu)

    return public_key, private_key


def encrypt(public_key, plaintext):
    n, g = public_key
    n_squared = n * n

    while True:
        r = random.randint(1, n - 1)
        if gcd(r, n) == 1:
            break

    ciphertext = (pow(g, plaintext, n_squared) * pow(r, n, n_squared)) % n_squared

    return ciphertext


def decrypt(public_key, private_key, ciphertext):
    n, g = public_key
    lambda_n, mu = private_key
    n_squared = n * n

    def L(x):
        return (x - 1) // n

    plaintext = (L(pow(ciphertext, lambda_n, n_squared)) * mu) % n

    return plaintext


def homomorphic_add(public_key, ciphertext1, ciphertext2):
    n, g = public_key
    n_squared = n * n

    result = (ciphertext1 * ciphertext2) % n_squared

    return result


def main():
    print("Paillier Encryption Scheme Implementation\n")

    print("Generating keypair...")
    public_key, private_key = generate_keypair(bits=512)
    print("Keys generated successfully.\n")

    # Get user input for the integers
    try:
        m1 = int(input("Enter the first integer: "))
        m2 = int(input("Enter the second integer: "))
    except ValueError:
        print("Invalid input. Please enter valid integers.")
        return

    print(f"\nOriginal integers: {m1} and {m2}")
    print(f"Expected sum: {m1 + m2}\n")

    print("Encrypting integers...")
    c1 = encrypt(public_key, m1)
    c2 = encrypt(public_key, m2)
    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}\n")

    print("Performing homomorphic addition on encrypted values...")
    c_sum = homomorphic_add(public_key, c1, c2)
    print(f"Encrypted sum: {c_sum}\n")

    print("Decrypting the result...")
    decrypted_sum = decrypt(public_key, private_key, c_sum)
    print(f"Decrypted sum: {decrypted_sum}\n")

    if decrypted_sum == m1 + m2:
        print("✓ Verification successful! The decrypted sum matches the original sum.")
    else:
        print("✗ Verification failed! The decrypted sum does not match.")


if __name__ == "__main__":
    main()
