from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import binascii


def ecc_keygen(curve: str = 'P-256') -> ECC.EccKey:
    return ECC.generate(curve=curve)


def ecc_encrypt(plaintext: str, recipient_public_key: ECC.EccKey):
    eph_private = ECC.generate(curve=recipient_public_key.curve)
    shared_point = recipient_public_key.pointQ * eph_private.d
    shared_x = int(shared_point.x)
    aes_key = SHA256.new(shared_x.to_bytes(32, 'big')).digest()

    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

    return {
        'ephemeral_pub_der': eph_private.public_key().export_key(format='DER'),
        'nonce': cipher.nonce,
        'tag': tag,
        'ciphertext': ciphertext,
    }


def ecc_decrypt(enc: dict, recipient_private_key: ECC.EccKey) -> str:
    eph_public = ECC.import_key(enc['ephemeral_pub_der'])
    shared_point = eph_public.pointQ * recipient_private_key.d
    shared_x = int(shared_point.x)
    aes_key = SHA256.new(shared_x.to_bytes(32, 'big')).digest()

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=enc['nonce'])
    plaintext = cipher.decrypt_and_verify(enc['ciphertext'], enc['tag'])
    return plaintext.decode('utf-8')


def main():
    print('Welcome to ECC (ECIES-style)')
    ptext = input('Enter plaintext: ')

    priv_key = ecc_keygen()
    pub_key = priv_key.public_key()

    print('\nPublic Key (Qx, Qy):')
    print('Qx =', hex(int(pub_key.pointQ.x)))
    print('Qy =', hex(int(pub_key.pointQ.y)))

    enc = ecc_encrypt(ptext, pub_key)
    print("\nYour ciphertext (hex):", binascii.hexlify(enc['ciphertext']).decode())

    decrypted = ecc_decrypt(enc, priv_key)
    print('Your decrypted plaintext:', decrypted)


if __name__ == '__main__':
    main()