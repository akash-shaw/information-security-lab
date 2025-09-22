from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate RSA key pair (for demonstration)
alice_key = RSA.generate(2048)
bob_key = RSA.generate(2048)

# Alice signs a document
document = b"Legal Document: Contract Agreement"
hash_doc = SHA256.new(document)
alice_signature = pkcs1_15.new(alice_key).sign(hash_doc)

# Bob verifies Alice's signature
try:
    pkcs1_15.new(alice_key.publickey()).verify(hash_doc, alice_signature)
    print("Alice's signature verified!")
except (ValueError, TypeError):
    print("Signature verification failed!")

# Bob signs a response
response_doc = b"Response Document: Approved"
hash_resp = SHA256.new(response_doc)
bob_signature = pkcs1_15.new(bob_key).sign(hash_resp)

# Alice verifies Bob's signature
try:
    pkcs1_15.new(bob_key.publickey()).verify(hash_resp, bob_signature)
    print("Bob's signature verified!")
except (ValueError, TypeError):
    print("Signature verification failed!")
