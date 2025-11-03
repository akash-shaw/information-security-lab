import socket
import hashlib


def main() -> None:
    host = "127.0.0.1"
    port = 5001

    message = b"hello integrity"
    tamper = False  # change to True to simulate corruption

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        send_data = message if not tamper else message[:-1] + b"X"
        s.sendall(send_data)

        server_digest = s.recv(128).decode()
        local_digest = hashlib.sha256(message).hexdigest()

        ok = (server_digest == local_digest)
        print("server:", server_digest)
        print("local :", local_digest)
        print("match :", ok)


if __name__ == "__main__":
    main()


