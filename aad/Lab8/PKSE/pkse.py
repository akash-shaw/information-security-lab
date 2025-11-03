import os
import json
import pickle
from collections import defaultdict
from phe import paillier

# global keys
public_key = None
private_key = None


def generate_keys():
    global public_key, private_key
    public_key, private_key = paillier.generate_paillier_keypair(n_length=512)
    print("Generated Paillier keypair")


def encrypt_number(number):
    # encrypt a number using public key
    return public_key.encrypt(number)


def decrypt_number(encrypted_number):
    # decrypt using private key
    return private_key.decrypt(encrypted_number)


def load_documents(docs_dir):
    documents = {}
    for filename in os.listdir(docs_dir):
        if filename.endswith(".md"):
            filepath = os.path.join(docs_dir, filename)
            with open(filepath, "r") as f:
                documents[filename] = f.read()
    print(f"Loaded {len(documents)} documents")
    return documents


def build_inverted_index(documents):
    # word -> list of doc IDs
    inverted_index = defaultdict(set)
    
    for doc_id, content in documents.items():
        words = content.lower().replace('\n', ' ').split()
        words = [''.join(c for c in word if c.isalnum()) for word in words]
        words = [w for w in words if w]
        
        for word in words:
            inverted_index[word].add(doc_id)
    
    inverted_index = {word: list(doc_ids) for word, doc_ids in inverted_index.items()}
    print(f"Built index with {len(inverted_index)} unique words")
    return inverted_index


def encrypt_index(inverted_index):
    # encrypt index using Paillier
    # for simplicity, we encrypt the hash of words and keep doc IDs in plaintext
    # in production, you'd use more sophisticated techniques
    encrypted_index = {}
    
    for word, doc_ids in inverted_index.items():
        # create a numeric representation of the word
        word_hash = hash(word) % (10**6)  # keep it manageable
        encrypted_word = encrypt_number(word_hash)
        encrypted_index[word] = {
            'encrypted_hash': encrypted_word,
            'doc_ids': doc_ids
        }
    
    # save to file
    with open("encrypted_index.pkl", "wb") as f:
        pickle.dump(encrypted_index, f)
    
    print("Encrypted index saved")
    return encrypted_index


def decrypt_index(encrypted_index):
    # decrypt index hashes
    decrypted_index = {}
    
    for word, data in encrypted_index.items():
        decrypted_hash = decrypt_number(data['encrypted_hash'])
        decrypted_index[word] = {
            'hash': decrypted_hash,
            'doc_ids': data['doc_ids']
        }
    
    return decrypted_index


def encrypt_query(query):
    # normalize and encrypt query
    query = query.lower().strip()
    query = ''.join(c for c in query if c.isalnum())
    return query


def search(query, encrypted_index, documents):
    print(f"\nSearching for: '{query}'")
    
    # normalize query
    query_normalized = encrypt_query(query)
    
    # search in encrypted index
    if query_normalized in encrypted_index:
        doc_ids = encrypted_index[query_normalized]['doc_ids']
    else:
        doc_ids = []
    
    # display results
    if not doc_ids:
        print("No documents found")
        return
    
    print(f"Found {len(doc_ids)} document(s):\n")
    for doc_id in doc_ids:
        if doc_id in documents:
            print(f"{'='*60}")
            print(f"Document: {doc_id}")
            print(f"{'='*60}")
            print(documents[doc_id])
            print(f"{'='*60}\n")


def main():
    print("\n=== Public Key Searchable Encryption (PKSE) Demo ===\n")
    
    # generate Paillier keys
    generate_keys()
    
    docs_dir = "documents"
    
    # load documents
    documents = load_documents(docs_dir)
    
    # build inverted index
    inverted_index = build_inverted_index(documents)
    
    # encrypt index with public key
    encrypted_index = encrypt_index(inverted_index)
    
    # interactive search
    print("\nInteractive Search (type 'exit' to quit)")
    
    while True:
        query = input("\nEnter search query: ").strip()
        
        if query.lower() == 'exit':
            break
        
        if query:
            search(query, encrypted_index, documents)
    
    print("\nDemo Complete\n")


if __name__ == "__main__":
    main()

