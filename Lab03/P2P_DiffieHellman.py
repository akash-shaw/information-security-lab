import random
import time

# -------------------------------
# Public parameters (prime and generator)
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
g = 2


# -------------------------------
# Peer 1 generates private and public keys
start_time = time.time()
private_key_1 = random.randint(2, p-2)
public_key_1 = pow(g, private_key_1, p)
key_gen_time_1 = time.time() - start_time

# Peer 2 generates private and public keys
start_time = time.time()
private_key_2 = random.randint(2, p-2)
public_key_2 = pow(g, private_key_2, p)
key_gen_time_2 = time.time() - start_time

# -------------------------------
# Key exchange and shared secret computation
start_time = time.time()
shared_secret_1 = pow(public_key_2, private_key_1, p)
shared_secret_2 = pow(public_key_1, private_key_2, p)
key_exchange_time = time.time() - start_time

# Verify both shared secrets are equal
assert shared_secret_1 == shared_secret_2

# -------------------------------
# Output results
print("Peer 1 Key Gen Time: {:.6f}s".format(key_gen_time_1))
print("Peer 2 Key Gen Time: {:.6f}s".format(key_gen_time_2))
print("Key Exchange Time: {:.6f}s".format(key_exchange_time))
print("Shared Secret (hex, first 64 bits):", hex(shared_secret_1)[:18])
