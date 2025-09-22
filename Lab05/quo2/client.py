# Using socket programming in Python, demonstrate the application of hash functions
# for ensuring data integrity during transmission over a network. Write server and client
# scripts where the server computes the hash of received data and sends it back to the
# client, which then verifies the integrity of the data by comparing the received hash with
# the locally computed hash. Show how the hash verification detects data corruption
# or tampering during transmission.



import socket


def custom_hash(input_string: str) -> int:
    hash_value = 5381
    for char in input_string:
        hash_value = ((hash_value * 33) + ord(char))
        hash_value ^= (hash_value >> 16)
    return hash_value & 0xFFFFFFFF


def send_data(data, host='localhost', port=65432, tamper=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # If tamper is True, corrupt the data before sending
        sent_data = data
        if tamper:
            sent_data = data[:-1] + ('X' if data[-1] != 'X' else 'Y')  # simple tampering

        print(f"Sending data: {sent_data}")
        s.sendall(sent_data.encode('utf-8'))

        # Receive hash from server
        server_hash = s.recv(1024).decode('utf-8')

        # Compute local hash from original data (not tampered)
        local_hash = custom_hash(data)

        print(f"Local hash:  {hex(local_hash)}")
        print(f"Server hash: {hex(int(server_hash))}")

        if int(server_hash) == local_hash:
            print("Data integrity verified: hashes match!")
        else:
            print("Data integrity compromised: hashes do NOT match!")


if __name__ == '__main__':
    # Example without tampering
    print("== Test without tampering ==")
    send_data("Hello, world!")

    print("\n== Test with tampering ==")
    send_data("Hello, world!", tamper=True)
