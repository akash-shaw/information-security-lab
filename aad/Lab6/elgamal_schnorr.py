import os
import random
from typing import Tuple

from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime


def elgamal_keygen(bits: int = 512) -> Tuple[Tuple[int, int, int], int]:
    p = getPrime(bits)
    g = random.randrange(2, p - 1)
    x = random.randrange(1, p - 1)
    h = pow(g, x, p)
    return (p, g, h), x

def elgamal_encrypt(message: bytes, pub_key: Tuple[int, int, int]) -> Tuple[int, int]:
    p, g, h = pub_key
    m = int.from_bytes(message, "big")
    if m >= p:
        raise ValueError("Message too large for key size")
    k = random.randrange(1, p - 1)
    c1 = pow(g, k, p)
    s = pow(h, k, p)
    c2 = (m * s) % p
    return c1, c2


def elgamal_decrypt(ciphertext: Tuple[int, int], priv_key: int, pub_key: Tuple[int, int, int]) -> bytes:
    c1, c2 = ciphertext
    p, _, _ = pub_key
    s = pow(c1, priv_key, p)
    s_inv = pow(s, p - 2, p)
    m = (c2 * s_inv) % p
    if m == 0:
        return b""
    m_len = (m.bit_length() + 7) // 8
    return m.to_bytes(m_len, "big")


def schnorr_keygen(bits: int = 512) -> Tuple[Tuple[int, int, int], int]:
    # Use same style group as ElGamal demo for simplicity
    p = getPrime(bits)
    g = random.randrange(2, p - 1)
    x = random.randrange(1, p - 1)
    y = pow(g, x, p)
    return (p, g, y), x


def schnorr_sign(message: bytes, priv_key: int, params: Tuple[int, int, int]) -> Tuple[int, int]:
    p, g, _ = params
    k = random.randrange(1, p - 1)
    r = pow(g, k, p)
    h = SHA256.new()
    h.update(r.to_bytes((r.bit_length() + 7) // 8 or 1, "big") + message)
    e = int.from_bytes(h.digest(), "big") % (p - 1)
    s = (k + e * priv_key) % (p - 1)
    return e, s


def schnorr_verify(message: bytes, signature: Tuple[int, int], params: Tuple[int, int, int]) -> bool:
    p, g, y = params
    e, s = signature
    # Compute r' = g^s * y^{-e} mod p
    y_inv_e = pow(y, (p - 1 - e) % (p - 1), p)
    r_prime = (pow(g, s, p) * y_inv_e) % p
    h = SHA256.new()
    h.update(r_prime.to_bytes((r_prime.bit_length() + 7) // 8 or 1, "big") + message)
    e_prime = int.from_bytes(h.digest(), "big") % (p - 1)
    return e_prime == e


def demo() -> None:
    print("Lab6: ElGamal (encrypt/decrypt) and Schnorr (sign/verify) demo")
    try:
        user_msg = input(f"Enter plaintext: ").strip()
    except EOFError:
        user_msg = ""
    message = (user_msg or default_msg).encode()

    # ElGamal
    pub_e, priv_e = elgamal_keygen(512)
    c1, c2 = elgamal_encrypt(message, pub_e)
    recovered = elgamal_decrypt((c1, c2), priv_e, pub_e)
    print("\nElGamal:")
    print(f"- Public: p({pub_e[0].bit_length()} bits), g, h")
    print(f"- Ciphertext c1={hex(c1)[:18]}..., c2={hex(c2)[:18]}...")
    print(f"- Decrypt OK: {recovered == message}")

    # Schnorr
    pub_s, priv_s = schnorr_keygen(512)
    sig = schnorr_sign(message, priv_s, pub_s)
    ok = schnorr_verify(message, sig, pub_s)
    print("\nSchnorr:")
    print(f"- Public: p({pub_s[0].bit_length()} bits), g, y")
    print(f"- Signature e={sig[0]}, s={sig[1]}")
    print(f"- Verify OK: {ok}")


if __name__ == "__main__":
    demo()


