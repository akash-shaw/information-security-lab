import os
import json
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- 1a. Create a Dataset ---
# A simple text corpus with 10 documents.
# The index of the list serves as the document ID.
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

# Generate a single, secure 32-byte secret key for both HMAC and AES
SECRET_KEY = get_random_bytes(32)

# --- 1b. Implement Encryption and Decryption Functions (AES-GCM) ---

def encrypt_aes_gcm(data, key):
    """
    Encrypts data using AES-GCM.
    Returns a dictionary containing ciphertext, nonce, and tag.
    """
    # Ensure data is in bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Return as a dictionary of hex-encoded strings for easy storage/serialization
    return {
        'ciphertext': ciphertext.hex(),
        'nonce': cipher.nonce.hex(),
        'tag': tag.hex()
    }

def decrypt_aes_gcm(encrypted_data, key):
    """
    Decrypts data encrypted with AES-GCM.
    Takes the dictionary from encrypt_aes_gcm as input.
    Returns the original plaintext as a string.
    """
    # Convert hex strings back to bytes
    ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
    nonce = bytes.fromhex(encrypted_data['nonce'])
    tag = bytes.fromhex(encrypted_data['tag'])
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    try:
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_bytes.decode('utf-8')
    except (ValueError, KeyError):
        print("Decryption failed. Data may be corrupt or key is incorrect.")
        return None

# --- Helper Functions for Searchable Index ---

def create_search_token(keyword, key):
    """
    Creates a deterministic token for a keyword using HMAC-SHA256.
    This ensures the same keyword always produces the same token.
    """
    return hmac.new(key, keyword.lower().encode('utf-8'), hashlib.sha256).hexdigest()

# --- 1c. Create and Encrypt an Inverted Index ---

def build_encrypted_inverted_index(docs, key):
    """
    Builds an inverted index and encrypts it for searchable encryption.
    - Index Keys (keywords) are tokenized using HMAC.
    - Index Values (doc ID lists) are encrypted using AES-GCM.
    """
    plaintext_index = {}
    encrypted_index = {}

    # 1. Build plaintext index
    for doc_id, doc_text in enumerate(docs):
        # Simple tokenization: lowercase and split by space
        words = doc_text.lower().split()
        for word in words:
            # remove basic punctuation
            clean_word = word.strip('.,?!')
            if clean_word not in plaintext_index:
                plaintext_index[clean_word] = []
            if doc_id not in plaintext_index[clean_word]:
                 plaintext_index[clean_word].append(doc_id)
    
    # 2. Encrypt the index
    for keyword, doc_ids in plaintext_index.items():
        # Create a deterministic token for the keyword
        keyword_token = create_search_token(keyword, key)
        
        # Serialize and encrypt the list of document IDs
        doc_ids_json = json.dumps(doc_ids)
        encrypted_doc_ids = encrypt_aes_gcm(doc_ids_json, key)
        
        # Store in the new encrypted index
        encrypted_index[keyword_token] = encrypted_doc_ids
        
    return encrypted_index

# --- 1d. Implement the Search Function ---

def search_encrypted_index(query, enc_index, key):
    """
    Searches the encrypted index for a query.
    - Encrypts the query to create a search token.
    - Finds matching encrypted document IDs.
    - Decrypts the document IDs.
    - Returns the list of original documents.
    """
    print(f"Searching for: '{query}'")
    
    # 1. Encrypt the query to get the search token
    query_token = create_search_token(query, key)
    
    # 2. Search the encrypted index for the token
    if query_token in enc_index:
        print("... Found a match in the encrypted index.")
        encrypted_result = enc_index[query_token]
        
        # 3. Decrypt the list of document IDs
        decrypted_doc_ids_json = decrypt_aes_gcm(encrypted_result, key)
        if decrypted_doc_ids_json:
            doc_ids = json.loads(decrypted_doc_ids_json)
            print(f"... Decrypted Document IDs: {doc_ids}\n")
            
            # 4. Retrieve and display the original documents
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
    print("--- Building and Encrypting the Inverted Index ---")
    encrypted_index = build_encrypted_inverted_index(documents, SECRET_KEY)
    print(f"Index built successfully. Total indexed keywords: {len(encrypted_index)}\n")
    
    # Example of what the encrypted index looks like (one item)
    # Note: We can't know which keyword this is without the key!
    sample_token = list(encrypted_index.keys())[0]
    print("--- Sample Encrypted Index Entry ---")
    print(f"Keyword Token: {sample_token}")
    print(f"Encrypted Doc IDs: {encrypted_index[sample_token]}\n")
    
    print("--- Performing Encrypted Searches ---\n")
    # --- Search for a word that appears in one document ---
    search_encrypted_index("fox", encrypted_index, SECRET_KEY)
    print("\n" + "="*40 + "\n")
    
    # --- Search for a word that appears in multiple documents ---
    search_encrypted_index("words", encrypted_index, SECRET_KEY)
    print("\n" + "="*40 + "\n")

    # --- Search for a word that does not exist ---
    search_encrypted_index("encryption", encrypted_index, SECRET_KEY)