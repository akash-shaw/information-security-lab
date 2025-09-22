import socket

# Hash function (same as server)
def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = ((hash_value * 33) + ord(char)) & 0xFFFFFFFF
    return hash_value

# Client configuration
HOST = '127.0.0.1'
PORT = 12345

# Message to send
message = "Hello, this is a test message split into multiple parts!"
# Split message into parts (for example, 10-character chunks)
parts = [message[i:i+10] for i in range(0, len(message), 10)]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((HOST, PORT))
    
    # Send each part
    for part in parts:
        client_socket.sendall(part.encode())
    
    # Close sending to signal end of message
    client_socket.shutdown(socket.SHUT_WR)
    
    # Receive hash from server
    received_hash = int(client_socket.recv(1024).decode())
    print(f"Hash received from server: {received_hash}")

    # Compute local hash
    local_hash = custom_hash(message)
    print(f"Local hash: {local_hash}")

    # Verify integrity
    if received_hash == local_hash:
        print("Message integrity verified! ✅")
    else:
        print("Message integrity failed! ❌")
