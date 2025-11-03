import random
from Crypto.Util.number import getPrime

def elgamal_keygen(bits=512):
    p = getPrime(bits)
    g = random.randint(2, p-1)
    x = random.randint(1, p-2)  # private key
    h = pow(g, x, p)  # public key component
    return (p, g, h), x

def elgamal_encrypt(message, pub_key):
    p, g, h = pub_key
    m = int.from_bytes(message.encode('utf-8'), 'big')
    if m >= p:
        raise ValueError("Message too large for key size")
    
    k = random.randint(1, p-2)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(ciphertext, priv_key, pub_key):
    c1, c2 = ciphertext
    p, g, h = pub_key
    x = priv_key
    
    s = pow(c1, x, p)
    s_inv = pow(s, p-2, p)  # modular inverse
    m = (c2 * s_inv) % p
    
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')

def main():
    print("Welcome to ElGamal")
    ptext = input("Enter plaintext: ")
    
    # Generate keys
    pub_key, priv_key = elgamal_keygen()
    p, g, h = pub_key
    
    print(f"\nPublic Key (p, g, h):")
    print(f"p = {hex(p)}")
    print(f"g = {g}")
    print(f"h = {hex(h)}")
    
    # Encrypt
    ctext = elgamal_encrypt(ptext, pub_key)
    print(f"\nCiphertext (c1, c2):")
    print(f"c1 = {hex(ctext[0])}")
    print(f"c2 = {hex(ctext[1])}")
    
    # Decrypt
    decrypted = elgamal_decrypt(ctext, priv_key, pub_key)
    print(f"Decrypted: {decrypted}")

if __name__ == '__main__':
    main()