# mini_demo.py
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes as rb

def gen_role(n):
    r = RSA.generate(2048)
    print(f"[keygen] role={n} RSA-2048")
    return {"name": n, "priv": r.export_key(), "pub": r.publickey().export_key()}

def ecdh_key():
    a, b = ECC.generate(curve="P-256"), ECC.generate(curve="P-256")
    s1 = (b.pointQ * a.d).x.to_bytes(32, "big")
    s2 = (a.pointQ * b.d).x.to_bytes(32, "big")
    assert s1 == s2
    k = SHA256.new(s1).digest()
    print(f"[ecdh] P-256 shared -> AES key {len(k)*8} bits")
    return k

def enc(k, m, aad=b""):
    n = rb(12); c = AES.new(k, AES.MODE_GCM, nonce=n); c.update(aad)
    ct, t = c.encrypt_and_digest(m)
    print(f"[enc] nonce={n.hex()} tag={t.hex()}")
    return n, ct, t

def dec(k, n, ct, t, aad=b""):
    c = AES.new(k, AES.MODE_GCM, nonce=n); c.update(aad)
    pt = c.decrypt_and_verify(ct, t)
    print(f"[dec] ok len={len(pt)}")
    return pt

def sign(role, msg):
    h = SHA256.new(msg)
    sig = pkcs1_15.new(RSA.import_key(role["priv"])).sign(h)
    print(f"[sign] by {role['name']} siglen={len(sig)}")
    return sig

def verify(pub, msg, sig):
    try:
        pkcs1_15.new(RSA.import_key(pub)).verify(SHA256.new(msg), sig)
        print("[verify] signature OK")
        return True
    except:
        print("[verify] signature FAIL")
        return False

def demo(s, r, msg):
    print(f"[demo] {s['name']} -> {r['name']}: {msg}")
    k = ecdh_key()
    hdr = f"{s['name']}->{r['name']}".encode()
    sig = sign(s, hdr)
    n, ct, t = enc(k, msg.encode(), hdr)
    assert verify(s["pub"], hdr, sig)
    pt = dec(k, n, ct, t, hdr).decode()
    print(f"[result] {pt}")

if __name__ == "__main__":
    a, b = gen_role("A"), gen_role("B")
    demo(a, b, "secret message")