import os
import socket

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def main() -> None:
    host = "127.0.0.1"
    port = 5003
    default_msg = os.environ.get("LAB6_MESSAGE", "rsa hello")
    try:
        user_msg = input(f"Enter plaintext [{default_msg}]: ").strip()
    except EOFError:
        user_msg = ""
    message = (user_msg or default_msg).encode()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as c:
        c.connect((host, port))
        # Receive server public key
        klen = int.from_bytes(recv_exact(c, 4), "big")
        kbytes = recv_exact(c, klen)
        server_pub = RSA.import_key(kbytes)

        # Encrypt message to server
        cipher = PKCS1_OAEP.new(server_pub)
        ctext = cipher.encrypt(message)
        c.sendall(len(ctext).to_bytes(4, "big") + ctext)

        # Receive acknowledgement
        rlen = int.from_bytes(recv_exact(c, 4), "big")
        reply = recv_exact(c, rlen)
        print("server reply:", reply.decode(errors="ignore"))


if __name__ == "__main__":
    main()

curl

