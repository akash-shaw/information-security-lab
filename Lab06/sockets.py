"""
Socket Programming Tutorial in Python
-------------------------------------
This code demonstrates basic client-server communication using sockets.
It includes:
1. A TCP server that listens for incoming connections
2. A TCP client that connects to the server
3. Sending and receiving messages
4. Extensive comments to explain every step

Concepts Covered:
- socket creation
- binding (server)
- listening (server)
- accepting connections (server)
- connecting (client)
- sending and receiving data
- closing sockets
"""

# ----------------- SERVER CODE -----------------
# The server waits for clients to connect, receives messages, and responds.

import socket  # Import the socket library
import threading  # To allow client and server to run simultaneously

def run_server():
    # 1. Create a TCP/IP socket
    # socket.AF_INET: IPv4 addresses
    # socket.SOCK_STREAM: TCP connection
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Server socket created.")

    # 2. Bind the socket to an IP and port
    # '' or '0.0.0.0' means listen on all network interfaces
    server_ip = 'localhost'  # For local testing
    server_port = 12345      # Port to listen on (1024-65535)
    server_socket.bind((server_ip, server_port))
    print(f"Server bound to IP {server_ip} and port {server_port}.")

    # 3. Listen for incoming connections
    # The parameter is the maximum number of queued connections
    server_socket.listen(5)
    print("Server listening for incoming connections...")

    # 4. Accept connections in a loop
    while True:
        client_conn, client_addr = server_socket.accept()
        # client_conn: new socket to communicate with the connected client
        # client_addr: IP and port of the client
        print(f"Connection established with {client_addr}")

        # Handle client in a separate thread
        threading.Thread(target=handle_client, args=(client_conn, client_addr)).start()

def handle_client(client_conn, client_addr):
    """
    Function to handle communication with a connected client
    """
    try:
        # 5. Receive data from client
        # 1024 bytes is the maximum amount of data to receive at once
        data = client_conn.recv(1024)
        print(f"Received from {client_addr}: {data.decode()}")  # Decode bytes to string

        # 6. Send a response to the client
        response = "Hello from server! Message received."
        client_conn.send(response.encode())  # Encode string to bytes before sending

    except Exception as e:
        print(f"Error with client {client_addr}: {e}")

    finally:
        # 7. Close client connection
        client_conn.close()
        print(f"Connection with {client_addr} closed.")


# ----------------- CLIENT CODE -----------------
# The client connects to the server and sends a message

def run_client():
    # 1. Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Client socket created.")

    # 2. Connect to the server
    server_ip = 'localhost'
    server_port = 12345
    client_socket.connect((server_ip, server_port))
    print(f"Client connected to server at {server_ip}:{server_port}")

    # 3. Send a message to the server
    message = "Hello server, this is client!"
    client_socket.send(message.encode())  # Encode string to bytes
    print("Message sent to server.")

    # 4. Receive response from server
    response = client_socket.recv(1024)  # Max 1024 bytes
    print(f"Response from server: {response.decode()}")  # Decode bytes to string

    # 5. Close the socket
    client_socket.close()
    print("Client socket closed.")


# ----------------- MAIN EXECUTION -----------------
# Run server and client in threads for demonstration

if __name__ == "__main__":
    # Start server thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Wait a moment to ensure server is listening
    import time
    time.sleep(1)

    # Run client
    run_client()

    # Allow some time for server to print messages before main thread ends
    time.sleep(2)
    print("Demo complete.")
