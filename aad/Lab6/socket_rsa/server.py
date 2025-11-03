import socket
from typing import Tuple

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa(bits: int = 2048) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    key = RSA.generate(bits)
    return key.publickey(), key


def main() -> None:
    host = "127.0.0.1"
    port = 5003

    pub, priv = generate_rsa(2048)
    pub_pem = pub.export_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind((host, port))
        srv.listen(1)
        conn, _ = srv.accept()
        with conn:
            # Send server public key
            conn.sendall(len(pub_pem).to_bytes(4, "big") + pub_pem)

            # Receive client's encrypted message
            clen = int.from_bytes(conn.recv(4), "big")
            ctext = conn.recv(clen)

            cipher = PKCS1_OAEP.new(priv)
            msg = cipher.decrypt(ctext)
            # Respond: encrypt reply with same public (client will not be able to decrypt without its private),
            # so just echo plaintext length as acknowledgement for demo.
            reply = f"received:{len(msg)}".encode()
            conn.sendall(len(reply).to_bytes(4, "big") + reply)


if __name__ == "__main__":
    main()


