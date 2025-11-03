from typing import Tuple

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF


def rfc3526_group14() -> Tuple[int, int]:
    p_hex = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
    )
    return int(p_hex, 16), 2


def int_to_fixed_length_bytes(value: int, length_bits: int) -> bytes:
    length_bytes = (length_bits + 7) // 8
    return value.to_bytes(length_bytes, byteorder="big")


def dh_keypair(p: int, g: int, private_bits: int = 256) -> Tuple[int, int]:
    from Crypto.Util import number

    a = 0
    while a < 2:
        a = number.getRandomNBitInteger(private_bits)
    A = pow(g, a, p)
    return a, A


def main() -> None:
    p, g = rfc3526_group14()
    a_priv, a_pub = dh_keypair(p, g)
    b_priv, b_pub = dh_keypair(p, g)

    a_shared = pow(b_pub, a_priv, p)
    b_shared = pow(a_pub, b_priv, p)
    same = (a_shared == b_shared)

    print("Lab6: Basic Diffie-Hellman (no symmetric cipher)")
    print(f"- Group: p({p.bit_length()} bits), g={g}")
    print(f"- A public: {hex(a_pub)[:18]}...")
    print(f"- B public: {hex(b_pub)[:18]}...")
    print(f"- Shared equal: {same}")

    # Optionally derive a fixed-length key material to show post-processing (not used to encrypt)
    shared_bytes = int_to_fixed_length_bytes(a_shared, p.bit_length())
    key_material = HKDF(shared_bytes, 32, salt=None, hashmod=SHA256, context=b"demo")
    print(f"- Derived key material (SHA256/HKDF) prefix: {key_material.hex()[:16]}...")


if __name__ == "__main__":
    main()


