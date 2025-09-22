import socket

# Hash function (DJB2 with 32-bit mask)
def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = ((hash_value * 33) + ord(char)) & 0xFFFFFFFF
    return hash_value

# Server configuration
HOST = '127.0.0.1'
PORT = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"Server listening on {HOST}:{PORT}")

    conn, addr = server_socket.accept()
    with conn:
        print(f"Connected by {addr}")
        message_parts = []

        while True:
            data = conn.recv(1024)
            if not data:
                break  # End of message
            message_parts.append(data.decode())

        # Reassemble message
        full_message = ''.join(message_parts)
        print(f"Received full message: {full_message}")

        # Compute hash
        message_hash = custom_hash(full_message)
        print(f"Computed hash: {message_hash}")

        # Send hash back to client
        conn.sendall(str(message_hash).encode())
