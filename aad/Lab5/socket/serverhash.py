import socket
import hashlib


def main() -> None:
    host = "127.0.0.1"
    port = 5001

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((host, port))
        server.listen(1)
        conn, addr = server.accept()
        with conn:
            data = conn.recv(4096)
            digest = hashlib.sha256(data).hexdigest()
            conn.sendall(digest.encode())


if __name__ == "__main__":
    main()


