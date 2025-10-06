import socket

# Client (Alice) parameters
p = 23  # prime modulus
g = 5   # base (generator)
a_private = 6
A = pow(g, a_private, p)

# Connect to server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 65432))

# Send Alice's public key to server
client.send(str(A).encode())

# Receive Bob's public key
B = int(client.recv(1024).decode())

# Compute shared secret
shared_secret_alice = pow(B, a_private, p)

print(f"Alice's shared secret: {shared_secret_alice}")
client.close()
