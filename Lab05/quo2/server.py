import socket


def custom_hash(input_string: str) -> int:
    hash_value = 5381
    for char in input_string:
        hash_value = ((hash_value * 33) + ord(char))
        hash_value ^= (hash_value >> 16)
    return hash_value & 0xFFFFFFFF


def start_server(host='localhost', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}")

        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            data = conn.recv(1024).decode('utf-8')
            if not data:
                return

            print(f"Received data: {data}")
            # Compute hash
            data_hash = custom_hash(data)
            print(f"Computed hash: {hex(data_hash)}")

            # Send the hash back to client
            conn.sendall(str(data_hash).encode('utf-8'))


if __name__ == '__main__':
    start_server()
