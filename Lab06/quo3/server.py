import socket

# Server (Bob) parameters
p = 23  # prime modulus
g = 5   # base (generator)
b_private = 15
B = pow(g, b_private, p)

# Start server and listen for client
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 65432))
server.listen(1)
print("Server listening on port 65432...")

conn, addr = server.accept()
print(f"Connection established with {addr}")

# Receive Alice's public key
A = int(conn.recv(1024).decode())

# Compute shared secret
shared_secret_bob = pow(A, b_private, p)

print(f"Bob's shared secret: {shared_secret_bob}")
conn.send(str(B).encode())  # Send Bob's public key

conn.close()
