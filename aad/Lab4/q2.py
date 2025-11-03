# pip install pycryptodome
import time, json
from Crypto.Util import number

log=[]

def blum_prime(bits):  # p ≡ 3 (mod 4)
    while True:
        p = number.getPrime(bits)
        if p % 4 == 3: return p

def keygen(bits=512, ttl=10):
    p, q = blum_prime(bits//2), blum_prime(bits//2)
    k = {"p":p, "q":q, "n":p*q, "exp":time.time()+ttl, "revoked":False}
    log.append({"t":time.time(), "ev":"KEYGEN", "n":k["n"]}); return k

def publish(k):
    log.append({"t":time.time(), "ev":"PUBLISH", "n":k["n"]}); return k["n"]

def revoke(k):
    k["revoked"] = True; log.append({"t":time.time(), "ev":"REVOKE"})

def expired(k): return time.time() > k["exp"]

def renew(k, ttl=10):
    revoke(k); k2 = keygen(bits=k["n"].bit_length(), ttl=ttl)
    log.append({"t":time.time(), "ev":"RENEW"}); return k2

def enc(m, n): return pow(m, 2, n)  # c = m^2 mod n

def dec(c, k):  # return one root via CRT (Rabin has 4 roots)
    p, q, n = k["p"], k["q"], k["n"]
    mp, mq = pow(c, (p+1)//4, p), pow(c, (q+1)//4, q)
    yp, yq = number.inverse(p, q), number.inverse(q, p)
    return (mp*q*yq + mq*p*yp) % n

# Demo
k = keygen(ttl=2); n = publish(k)
m = 123456789
c = enc(m, n); m1 = dec(c, k)
print("ok:", m == m1)

time.sleep(2.1)  # simulate expiry
if expired(k) or k["revoked"]:
    k = renew(k, ttl=5); n = publish(k)

c2 = enc(m, n); m2 = dec(c2, k)
print("ok2:", m == m2)
print(json.dumps(log, indent=2))