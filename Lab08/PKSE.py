import json
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5  # We will NOT use this, but show a point
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime

# --- Helper functions for "Textbook" (Insecure) RSA ---

def textbook_rsa_encrypt(message_bytes, public_key):
    """
    Encrypts a byte string using insecure, deterministic "textbook" RSA.
    This is (message ^ e) % n.
    """
    # 1. Convert byte string to a large integer
    m = bytes_to_long(message_bytes)
    
    # 2. Perform the raw RSA operation (no padding)
    c = pow(m, public_key.e, public_key.n)
    return c

def textbook_rsa_decrypt(ciphertext_int, private_key):
    """
    Decrypts a ciphertext integer using insecure "textbook" RSA.
    This is (ciphertext ^ d) % n.
    """
    # 1. Perform the raw RSA operation (no padding)
    m = pow(ciphertext_int, private_key.d, private_key.n)
    
    # 2. Convert the integer back to bytes
    try:
        return long_to_bytes(m)
    except Exception as e:
        print(f"Decryption error (ciphertext may be invalid): {e}")
        return None

# --- 1a. Create a Dataset ---
documents = [
    "The quick brown fox jumps over the lazy dog",
    "A journey of a thousand miles begins with a single step",
    "All that glitters is not gold",
    "Actions speak louder than words",
    "The early bird catches the worm",
    "Where there is a will there is a way",
    "The pen is mightier than the sword",
    "When in Rome do as the Romans do",
    "A picture is worth a thousand words",
    "The squeaky wheel gets the grease, and the lazy fox gets nothing"
]

# --- 2b. Implement (Flawed) Encryption Functions ---
# Generate a 2048-bit RSA key pair
print("Generating RSA key pair (this may take a moment)...")
key = RSA.generate(2048)
public_key = key.publickey()
private_key = key
print("Key generation complete.\n")

# --- 2c. Create an Encrypted Index ---

def build_encrypted_index(docs, pub_key, priv_key):
    """
    Builds an inverted index using insecure deterministic RSA.
    - Index Keys (keywords) are encrypted with the public key.
    - Index Values (doc ID lists) are ALSO encrypted with the public key.
    This is deeply insecure, but follows the prompt's logic.
    """
    plaintext_index = {}
    encrypted_index = {}

    # 1. Build plaintext index
    for doc_id, doc_text in enumerate(docs):
        for word in doc_text.lower().split():
            clean_word = word.strip('.,?!')
            if clean_word not in plaintext_index:
                plaintext_index[clean_word] = []
            if doc_id not in plaintext_index[clean_word]:
                 plaintext_index[clean_word].append(doc_id)
    
    print("Plaintext index built. Now encrypting...")
    
    # 2. Encrypt the index
    for keyword, doc_ids in plaintext_index.items():
        
        # Encrypt the keyword (string)
        # This is the "searchable" part.
        keyword_bytes = keyword.encode('utf-8')
        encrypted_keyword_int = textbook_rsa_encrypt(keyword_bytes, pub_key)
        
        # Encrypt the document ID list (the "value")
        # We serialize the list to a JSON string first
        doc_ids_json = json.dumps(doc_ids)
        encrypted_doc_ids_int = textbook_rsa_encrypt(doc_ids_json.encode('utf-8'), pub_key)
        
        # Store in the new encrypted index
        # The key and value are both large integers (ciphertexts)
        encrypted_index[encrypted_keyword_int] = encrypted_doc_ids_int
        
    print("Encrypted index created.\n")
    return encrypted_index

# --- 2d. Implement the Search Function ---

def search_encrypted_index(query, enc_index, pub_key, priv_key):
    """
    Searches the deterministically encrypted index.
    """
    print(f"Searching for: '{query}'")
    
    # 1. Encrypt the query using the public key
    # Because encryption is deterministic, this will match the index key
    query_bytes = query.lower().encode('utf-8')
    encrypted_query_int = textbook_rsa_encrypt(query_bytes, pub_key)
    
    # 2. Search the encrypted index for a matching term (ciphertext)
    if encrypted_query_int in enc_index:
        print("... Found a match in the encrypted index.")
        encrypted_result_int = enc_index[encrypted_query_int]
        
        # 3. Decrypt the returned document IDs using the private key
        decrypted_doc_ids_bytes = textbook_rsa_decrypt(encrypted_result_int, priv_key)
        
        if decrypted_doc_ids_bytes:
            doc_ids = json.loads(decrypted_doc_ids_bytes.decode('utf-8'))
            print(f"... Decrypted Document IDs: {doc_ids}\n")
            
            # 4. Display the corresponding documents
            print("--- Corresponding Documents ---")
            for doc_id in doc_ids:
                print(f"  [Doc {doc_id}]: {documents[doc_id]}")
            print("-----------------------------")
        else:
            print("... Could not decrypt the result.")
    else:
        print("... No results found for your query.")

# --- Main Execution ---

if __name__ == "__main__":
    
    print("--- Building and Encrypting the Index (Insecurely) ---")
    encrypted_index = build_encrypted_index(documents, public_key, private_key)
    
    print("--- Performing Encrypted Searches ---\n")
    
    # --- Search for a word that appears in one document ---
    search_encrypted_index("fox", encrypted_index, public_key, private_key)
    print("\n" + "="*40 + "\n")
    
    # --- Search for a word that appears in multiple documents ---
    search_encrypted_index("words", encrypted_index, public_key, private_key)
    print("\n" + "="*40 + "\n")

    # --- Search for a word that does not exist ---
    search_encrypted_index("paillier", encrypted_index, public_key, private_key)