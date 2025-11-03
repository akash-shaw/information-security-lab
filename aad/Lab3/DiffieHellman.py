import time
from dataclasses import dataclass

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util import number


def rfc3526_group14() -> tuple[int, int]:
    """
    Return the 2048-bit MODP Group (Group 14) parameters from RFC 3526.

    g = 2
    p is the safe prime specified in RFC 3526, section 3.
    """
    # RFC 3526 Group 14 (2048-bit MODP) prime (hex, concatenated)
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
    p = int(p_hex, 16)
    g = 2
    return p, g


def int_to_fixed_length_bytes(value: int, length_bits: int) -> bytes:
    length_bytes = (length_bits + 7) // 8
    return value.to_bytes(length_bytes, byteorder="big")


def generate_keypair(p: int, g: int, private_bits: int = 256) -> tuple[int, int]:
    a = 0
    while a < 2:
        a = number.getRandomNBitInteger(private_bits)
    A = pow(g, a, p)
    return a, A


def derive_shared_key(peer_public: int, private: int, p: int, key_len: int = 32) -> bytes:
    shared_secret = pow(peer_public, private, p)
    # Use fixed-length big-endian encoding of the shared secret for KDF input
    shared_bytes = int_to_fixed_length_bytes(shared_secret, p.bit_length())
    key = HKDF(shared_bytes, key_len, salt=None, hashmod=SHA256, context=b"DH key")
    return key


class TimingResult:
    alice_keygen_s: float
    bob_keygen_s: float
    alice_exchange_s: float
    bob_exchange_s: float


def measure_timings(p: int, g: int, private_bits: int = 256) -> TimingResult:
    start = time.perf_counter()
    a_priv, a_pub = generate_keypair(p, g, private_bits)
    alice_keygen_s = time.perf_counter() - start

    start = time.perf_counter()
    b_priv, b_pub = generate_keypair(p, g, private_bits)
    bob_keygen_s = time.perf_counter() - start

    # Exchange
    start = time.perf_counter()
    a_key = derive_shared_key(b_pub, a_priv, p)
    alice_exchange_s = time.perf_counter() - start

    start = time.perf_counter()
    b_key = derive_shared_key(a_pub, b_priv, p)
    bob_exchange_s = time.perf_counter() - start

    # Sanity check
    if a_key != b_key:
        raise RuntimeError("Derived keys do not match. Check parameters.")

    return TimingResult(
        alice_keygen_s=alice_keygen_s,
        bob_keygen_s=bob_keygen_s,
        alice_exchange_s=alice_exchange_s,
        bob_exchange_s=bob_exchange_s,
    )


def main():
    p, g = rfc3526_group14()

    timings = measure_timings(p, g, private_bits=256)

    print("Diffie-Hellman (RFC3526 Group 14, g=2)")
    print(f"Prime bits: {p.bit_length()}\n")

    print("Timings (seconds):")
    print(f"- Alice key generation: {timings.alice_keygen_s:.6f}")
    print(f"- Bob   key generation: {timings.bob_keygen_s:.6f}")
    print(f"- Alice key exchange:   {timings.alice_exchange_s:.6f}")
    print(f"- Bob   key exchange:   {timings.bob_exchange_s:.6f}")


if __name__ == "__main__":
    main()