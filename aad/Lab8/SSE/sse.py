import os
import json
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

AES_KEY = get_random_bytes(32)  # 256-bit key


def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    iv = cipher.iv
    if isinstance(data, str):
        data = data.encode('utf-8')
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return iv + encrypted


def decrypt_data(encrypted_data):
    iv = encrypted_data[:16]
    encrypted = encrypted_data[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted


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
    # serialize and encrypt
    serialized = json.dumps(inverted_index).encode('utf-8')
    encrypted = encrypt_data(serialized)
    with open("encrypted_index.bin", "wb") as f:
        f.write(encrypted)
    print("Encrypted index saved")
    return encrypted


def decrypt_index(encrypted_index):
    decrypted = decrypt_data(encrypted_index)
    inverted_index = json.loads(decrypted.decode('utf-8'))
    return inverted_index


def search(query, encrypted_index_data, documents):
    print(f"\nSearching for: '{query}'")
    
    # decrypt index
    inverted_index = decrypt_index(encrypted_index_data)
    
    # normalize query
    query_normalized = query.lower().strip()
    query_normalized = ''.join(c for c in query_normalized if c.isalnum())
    
    # search
    doc_ids = inverted_index.get(query_normalized, [])
    
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
    print("\n=== Searchable Symmetric Encryption Demo ===\n")
    
    docs_dir = "documents"
    
    # load documents
    documents = load_documents(docs_dir)
    
    # build inverted index
    inverted_index = build_inverted_index(documents)
    
    # encrypt index
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
