from hashlib import sha256

# Parameters
p = 23  # prime
q = 11  # prime divisor of p-1
g = 2
x = 6   # private key
y = pow(g, x, p)  # public key

# Signing
m = "Hello"
k = 3
r = pow(g, k, p)
e = int(sha256((str(r)+m).encode()).hexdigest(), 16) % q
s = (k - x*e) % q

# Verification
v = (pow(g, s, p) * pow(y, e, p)) % p
e_ver = int(sha256((str(v)+m).encode()).hexdigest(), 16) % q
print("Schnorr signature verified!" if e_ver == e else "Verification failed!")
