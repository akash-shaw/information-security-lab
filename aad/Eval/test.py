from functools import partial
import time
import numpy as np
import string
import matplotlib.pyplot as plt
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from sympy import Matrix   # only for the 2×2 Hill inverse


# 1.  Hill-Cipher utilities  (2×2 matrix [[3,3],[2,5]])

hillkey = np.array([[3, 3],
                    [2, 5]], dtype=int)
ALPH = string.ascii_uppercase
m_len = 2                         # block size

def clean(txt):
    return ''.join(ch.upper() for ch in txt if ch.isalpha())

def hill_encrypt(pt, key=hillkey):
    pt = clean(pt)
    if len(pt) % m_len:                       # padding
        pt += 'X' * (m_len - len(pt) % m_len)
    cipher = []
    for i in range(0, len(pt), m_len):
        block = np.array([ALPH.index(ch) for ch in pt[i:i+m_len]])
        cipher.extend((key @ block) % 26)
    return ''.join(ALPH[i] for i in cipher)

def hill_decrypt(ct, key=hillkey):
    # modular inverse of the matrix
    M = Matrix(key)
    detinv = pow(int(M.det()) % 26, -1, 26)
    adj = M.adjugate()
    inv_key = (detinv * adj) % 26
    inv_key = np.array(inv_key).astype(int)

    plain = []
    for i in range(0, len(ct), m_len):
        block = np.array([ALPH.index(ch) for ch in ct[i:i+m_len]])
        plain.extend((inv_key @ block) % 26)
    return ''.join(ALPH[i] for i in plain)

# Generic timing wrapper
def timed(fn, *a, **kw):
    t0 = time.perf_counter()
    for _ in range(100_000):              # 100 000 loops → 1 000 000 calls
        fn(*a, **kw)
    delta = time.perf_counter() - t0
    return delta

# Menu
def menu():
    while True:
        print("\n===== Cryptographic Demo =====")
        print("1. Hill-cipher demo")
        print("2. RSA + envelope (share AES)")
        print("3. AES-128 encrypt / decrypt")
        print("4. Speed graph (100k it loops)")
        print("0. Quit")
        ch = input("Select >> ").strip()
        if ch == '0': break
        elif ch == '1': hill_demo()
        elif ch == '2': rsa_env_demo()
        elif ch == '3': aes_demo()
        elif ch == '4': speed_graph()
        else: print("Invalid choice")

# 1.  Hill demo
def hill_demo():
    msg = 'The  key is hidden under the mattress'
    print("\n------- 1. Hill-Cipher Demo -------")
    print("Key matrix:\n", hillkey)
    ct = hill_encrypt(msg)
    print("Cipher :", ct)
    pt = hill_decrypt(ct)
    print("Plain  :", pt)       # uppercase / padded – expected

# 2. RSA Envelope demo
AES_KEY = b"0123456789ABCDEF"    # 16-byte AES-128 key (truncated from prompt)

def rsa_env_demo():
    print("\n------- 2. RSA × AES envelope Demo -------")
    # generate RSA pairs
    encoder_priv = RSA.generate(2048)
    encoder_pub  = encoder_priv.publickey()

    decoder_priv = RSA.generate(2048)   # strictly not needed, but shown
    decoder_pub  = decoder_priv.publickey()

    # Use encoder_pub to encrypt the shared AES key
    cipher_rsa = PKCS1_OAEP.new(encoder_pub)
    enc_key = cipher_rsa.encrypt(AES_KEY)

    # Show keys
    print("Encoder public key (PEM):\n", encoder_pub.export_key().decode())
    print("Encoder private key (PEM):\n", encoder_priv.export_key().decode())
    print("Encrypted AES key (hex):", enc_key.hex())

    # Decrypt back using encoder’s private key
    dec_rsa = PKCS1_OAEP.new(encoder_priv)
    dec_key = dec_rsa.decrypt(enc_key)
    print("Decrypted AES key        :", dec_key.hex(), " match=", dec_key==AES_KEY)

# 3. AES-128
def aes_demo():
    msg = input("Enter AES plaintext:")
    print("\n------- 3. AES-128 Demo -------")
    cipher = AES.new(AES_KEY, AES.MODE_CBC)         # random IV
    ct = cipher.encrypt(pad(msg.encode(), AES.block_size))
    print("Raw key               :", AES_KEY.hex())
    print("Ciphertext (incl. IV) :", cipher.iv.hex() + ct.hex())
    decipher = AES.new(AES_KEY, AES.MODE_CBC, cipher.iv)
    pt = unpad(decipher.decrypt(ct), AES.block_size).decode()
    print("Recovered plaintext   :", pt)

# 4.  Speed test
def speed_graph():
    print("\n------- Benchmark (100 000 loops = 1 Mio calls) -------")
    # prepare one big dummy block for AES
    aes_cipher = AES.new(AES_KEY, AES.MODE_ECB)
    dummy_aes = b"A" * 16

    # RSA encryption of AES key just once
    pub_key = RSA.generate(2048).publickey()
    rsa_cipher = PKCS1_OAEP.new(pub_key)
    dummy_rsa = AES_KEY

    # Hill needs string
    hill_string = "HELLOWORLD"
    hill_ct = hill_encrypt(hill_string)   # pre-compute to keep test same

    # timing
    t_hill = timed(hill_encrypt, hill_string)
    t_rsa  = timed(rsa_cipher.encrypt, dummy_rsa)
    t_aes  = timed(aes_cipher.encrypt, dummy_aes)

    methods = ['Hill-cipher\n(str encrypt)', 'RSA-OAEP\n(key wrap)', 'AES-128\n(block)']
    timings = [t_hill, t_rsa, t_aes]
    for name,val in zip(methods,timings):
        print(f"{name:25s} : {val:9.4f} s (100 000 loops)")

    plt.bar(methods, timings, color=['gold','coral','dodgerblue'])
    plt.ylabel("Time (s) for 100 000 iterations")
    plt.title("Relative speed among 3 algorithms")
    plt.tight_layout()
    plt.show()

##############################################################
# main
##############################################################
if __name__ == "__main__":
    menu()
