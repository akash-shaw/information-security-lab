from phe import paillier

# Generate public and private keys
public_key, private_key = paillier.generate_paillier_keypair()

# Sample documents
documents = {
    "doc1": "This is the first document with some words",
    "doc2": "The second document has different content",
    "doc3": "This document is another example of the data corpus",
    "doc4": "Words in this document are mixed up to create variety",
    "doc5": "This one has words like search and encryption",
    "doc6": "Searching for documents through encrypted data is possible",
    "doc7": "Encryption techniques enable searchability on private data",
    "doc8": "Public-key cryptography is a powerful tool",
    "doc9": "This is the ninth document with some more words",
    "doc10": "Final document with encryption related terms"
}


# Encryption and decryption functions
def encrypt_data(public_key, data):
    """Encrypt the data using the Paillier public key."""
    encrypted_data = [public_key.encrypt(int(hash(word))) for word in data.split()]
    return encrypted_data


def decrypt_data(private_key, encrypted_data):
    """Decrypt the data using the Paillier private key."""
    decrypted_data = [private_key.decrypt(encrypted_word) for encrypted_word in encrypted_data]
    return decrypted_data


# Create an encrypted index
def create_encrypted_index(documents, public_key):
    """Create an encrypted inverted index using Paillier encryption."""
    index = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            encrypted_word = encrypt_data(public_key, word)[0]
            if encrypted_word not in index:
                index[encrypted_word] = []
            index[encrypted_word].append(doc_id)
    return index


# Search function
def search(encrypted_index, query, public_key, private_key):
    """Search the encrypted index with an encrypted query."""
    encrypted_query = encrypt_data(public_key, query)[0]  # Encrypt query word
    if encrypted_query in encrypted_index:
        encrypted_doc_ids = encrypted_index[encrypted_query]
        decrypted_doc_ids = decrypt_data(private_key,
                                         [public_key.encrypt(int(hash(doc_id))) for doc_id in encrypted_doc_ids])
        return decrypted_doc_ids
    else:
        return []


# Main experiment to test PKSE
def run_experiment():
    print("Generating encrypted index...")
    encrypted_index = create_encrypted_index(documents, public_key)

    query = "document"  # Example query
    print(f"Searching for the query: '{query}'")

    results = search(encrypted_index, query, public_key, private_key)

    print(f"Documents containing the query '{query}':")
    for doc in results:
        print(doc)


if __name__ == "__main__":
    run_experiment()
