from Crypto.Random import random
from Crypto.Util.number import getPrime, inverse

# ElGamal key generation
p = getPrime(256)
g = 2
x = random.randint(2, p-2)   # private key
y = pow(g, x, p)             # public key

# Signing a message
m = 123  # message as integer
k = random.randint(2, p-2)
r = pow(g, k, p)
s = (inverse(k, p-1) * (m - x*r)) % (p-1)

# Verification
v1 = pow(g, m, p)
v2 = (pow(y, r, p) * pow(r, s, p)) % p
print("ElGamal signature verified!" if v1 == v2 else "Verification failed!")
