#!/usr/bin/env python3

import socket
import threading
import json
import base64
import time
import random
from math import gcd
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# --- Paillier Cryptosystem Implementation ---
def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False
    
    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = (x * x) % n
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        if n % 2 == 0:
            n += 1
        if is_prime(n):
            return n

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

class PaillierKey:
    def __init__(self, bits=1024):
        # Generate two large prime numbers
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        
        # Compute n = p * q
        self.n = p * q
        self.n_sq = self.n * self.n
        
        # Compute λ = lcm(p-1, q-1)
        self.lambda_ = lcm(p-1, q-1)
        
        # Compute g = n + 1
        self.g = self.n + 1
        
        # Compute μ = λ^-1 mod n
        self.mu = pow(self.lambda_, -1, self.n)

    def encrypt(self, m):
        if not 0 <= m < self.n:
            raise ValueError("Message must be in range [0, n)")
        
        # Choose random r in Z*_n
        r = random.randrange(1, self.n)
        while gcd(r, self.n) != 1:
            r = random.randrange(1, self.n)
        
        # Compute ciphertext
        c = (pow(self.g, m, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return PaillierCiphertext(c, self.n_sq)
    
    def decrypt(self, c):
        if not isinstance(c, PaillierCiphertext) and isinstance(c, int):
            c = PaillierCiphertext(c, self.n_sq)
        
        # Decrypt using CRT
        x = pow(c.value, self.lambda_, self.n_sq)
        L = (x - 1) // self.n
        m = (L * self.mu) % self.n
        return m

class PaillierCiphertext:
    def __init__(self, value, n_sq):
        self.value = value
        self.n_sq = n_sq
    
    def __add__(self, other):
        if isinstance(other, PaillierCiphertext):
            return PaillierCiphertext((self.value * other.value) % self.n_sq, self.n_sq)
        return NotImplemented
    
    def __mul__(self, scalar):
        if isinstance(scalar, int):
            return PaillierCiphertext(pow(self.value, scalar, self.n_sq), self.n_sq)
        return NotImplemented
    
    def ciphertext(self):
        return self.value

# --- Global Configuration ---
HOST = '127.0.0.1'  # localhost
PORT = 65432

# We will generate the server's Paillier key pair once and store it globally
# so all handler threads can access it for decryption.
server_paillier_key = None

# Thread-safe lock for printing summaries
print_lock = threading.Lock()

# ==============================================================================
# === 1. PAYMENT GATEWAY (SERVER) CODE
# ==============================================================================

def handle_seller(conn, addr):
    """
    Handles a single connection from a seller.
    This function is run in a separate thread for each client.
    """
    global server_paillier_key
    
    print(f"[Gateway] New connection from {addr}")
    client_rsa_pub = None
    
    try:
        # 1. Receive the Seller's RSA Public Key
        # The seller needs this to sign their transaction summary.
        client_rsa_pem = conn.recv(1024)
        if not client_rsa_pem:
            raise ConnectionError("Client disconnected before sending RSA key")
        client_rsa_pub = RSA.import_key(client_rsa_pem)
        
        # 2. Send the Server's Paillier Public Key (just 'n')
        # The seller will use this to encrypt transaction amounts.
        conn.sendall(str(server_paillier_key.n).encode('utf-8'))
        
        # 3. Receive the complete transaction payload from the seller
        # This payload contains the signed data and the signature itself.
        payload_bytes = conn.recv(4096) # Increase buffer for larger payloads
        if not payload_bytes:
            raise ConnectionError("Client disconnected before sending payload")
            
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        data_signed = payload['data']
        signature_b64 = payload['signature_b64']
        signature = base64.b64decode(signature_b64)

        # --- 4. Digital Signature Verification (RSA + SHA-256) ---
        
        # We must re-serialize the data *exactly* as the client did to get the same hash.
        # `sort_keys=True` ensures a canonical representation.
        data_bytes = json.dumps(data_signed, sort_keys=True).encode('utf-8')
        h = SHA256.new(data_bytes)
        
        verification_result = ""
        try:
            pkcs1_15.new(client_rsa_pub).verify(h, signature)
            verification_result = "SUCCESS"
        except (ValueError, TypeError):
            verification_result = "FAILED - SIGNATURE INVALID"

        # --- 5. Paillier Homomorphic Decryption ---
        
        # The server uses its *private* Paillier key to decrypt.
        # We must reconstruct the Ciphertext objects from the integers sent by the client.
        # The Paillier private key object (`server_paillier_key`) has access to `_n2` (n*n).

        # Decrypt individual transactions
        decrypted_individuals = []
        for c_str in data_signed['encrypted_ciphertexts_str']:
            c_int = int(c_str)
            # Decrypt the integer directly
            decrypted_individuals.append(server_paillier_key.decrypt(c_int))

        # Decrypt the homomorphically added total
        total_c_int = int(data_signed['total_encrypted_ciphertext_str'])
        total_decrypted = server_paillier_key.decrypt(total_c_int)

        # --- 6. Output Final Transaction Summary ---
        # Use a lock to prevent jumbled output from multiple threads
        with print_lock:
            print("\n" + "="*80)
            print(f"--- TRANSACTION SUMMARY FOR: {data_signed['seller_name']} (from {addr}) ---")
            print("="*80)
            
            print("\n** 1. Seller & Original Transactions **")
            print(f"  Seller Name:     {data_signed['seller_name']}")
            print(f"  Plaintext Txns:  {data_signed['transactions']}")
            
            print("\n** 2. Paillier Encryption Details **")
            for i in range(len(data_signed['transactions'])):
                print(f"  Txn {i+1} Plaintext:   {data_signed['transactions'][i]}")
                print(f"  Txn {i+1} Encrypted:   {data_signed['encrypted_ciphertexts_str'][i][:40]}...") # Truncate for display
                print(f"  Txn {i+1} Decrypted:   {decrypted_individuals[i]}")
                print("  ---")
            
            print("** 3. Homomorphic Total **")
            print(f"  Total Encrypted (Homomorphic Sum): {data_signed['total_encrypted_ciphertext_str'][:40]}...")
            print(f"  Total Decrypted (from Sum):      {total_decrypted}")
            
            # Verify the math
            plain_sum = sum(data_signed['transactions'])
            print(f"  Verification (Plaintext Sum):    {plain_sum}")
            print(f"  Total Amounts Match:             {plain_sum == total_decrypted}")

            print("\n** 4. Digital Signature & Verification (RSA-2048 + SHA-256) **")
            print(f"  Signature Status:          Received")
            print(f"  Signature Verification:    ** {verification_result} **")
            print("="*80 + "\n")

    except Exception as e:
        print(f"[Gateway] Error handling client {addr}: {e}")
    finally:
        print(f"[Gateway] Closing connection from {addr}")
        conn.close()

def gateway_server():
    """
    The main server loop.
    Initializes Paillier keys and listens for seller connections.
    """
    global server_paillier_key, server_paillier_n
    
    # Generate the server's Paillier key pair (1024-bit for speed in demo)
    print("[Gateway] Generating 1024-bit Paillier key pair...")
    server_paillier_key = PaillierKey(1024)
    print("[Gateway] Paillier key pair generated.")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5) # Allow up to 5 queued connections
        print(f"[Gateway] Payment Gateway Server listening on {HOST}:{PORT}")
        
        try:
            while True:
                conn, addr = s.accept()
                # Start a new thread to handle this seller
                handler_thread = threading.Thread(
                    target=handle_seller, 
                    args=(conn, addr)
                )
                handler_thread.start()
        except KeyboardInterrupt:
            print("\n[Gateway] Shutting down server...")
        finally:
            s.close()

# ==============================================================================
# === 2. SELLER (CLIENT) CODE
# ==============================================================================

def run_seller(seller_name, transactions):
    """
    Simulates a single seller connecting to the gateway,
    encrypting transactions, signing the summary, and sending it.
    """
    print(f"[{seller_name}] Starting...")
    
    try:
        # 1. Generate this seller's RSA key pair for signing
        # (2048-bit is a standard, secure size)
        rsa_key = RSA.generate(2048)
        rsa_pub_key_pem = rsa_key.publickey().export_key()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # 2. Connect to the Gateway Server
            s.connect((HOST, PORT))
            
            # 3. Send our RSA Public Key
            s.sendall(rsa_pub_key_pem)
            
            # 4. Receive the Gateway's Paillier Public Key ('n')
            n_str = s.recv(1024).decode('utf-8')
            n = int(n_str)
            
            # Create Paillier encryption-only key using received 'n'
            paillier_pub = PaillierKey()
            paillier_pub.n = n
            paillier_pub.n_sq = n * n
            paillier_pub.g = n + 1

            # --- 5. Paillier Encryption & Homomorphic Addition ---
            encrypted_txns_ints = []
            
            # Initialize the homomorphic sum with an encryption of 0
            total_encrypted_obj = paillier_pub.encrypt(0) 

            print(f"[{seller_name}] Encrypting {len(transactions)} transactions...")
            for tx_amount in transactions:
                # Encrypt the amount
                enc_tx = paillier_pub.encrypt(tx_amount)
                
                # Store the integer representation (for sending)
                encrypted_txns_ints.append(enc_tx.ciphertext())
                
                # Homomorphically add this amount to the total
                total_encrypted_obj = total_encrypted_obj + enc_tx

            total_encrypted_int = total_encrypted_obj.ciphertext()
            
            # --- 6. Create Transaction Summary to be Signed ---
            
            # Note: We must convert the large integers to strings to make
            # them JSON-serializable.
            data_to_sign = {
                "seller_name": seller_name,
                "transactions": transactions,
                "encrypted_ciphertexts_str": [str(x) for x in encrypted_txns_ints],
                "total_encrypted_ciphertext_str": str(total_encrypted_int),
            }
            
            # --- 7. Sign the Summary (RSA + SHA-256) ---
            
            # Serialize the data to a canonical JSON string
            # `sort_keys=True` is CRITICAL for the signature to be verifiable
            data_bytes = json.dumps(data_to_sign, sort_keys=True).encode('utf-8')
            
            # Hash the JSON string
            h = SHA256.new(data_bytes)
            
            # Sign the hash with our RSA private key
            signer = pkcs1_15.new(rsa_key)
            signature = signer.sign(h)
            
            # --- 8. Create Final Payload and Send ---
            
            # Base64-encode the binary signature to make it JSON-serializable
            final_payload = {
                "data": data_to_sign,
                "signature_b64": base64.b64encode(signature).decode('utf-8')
            }
            
            # Send the complete package to the server
            s.sendall(json.dumps(final_payload).encode('utf-8'))
            
            print(f"[{seller_name}] Transaction bundle sent successfully.")

    except Exception as e:
        print(f"[{seller_name}] ERROR: {e}")

# ==============================================================================
# === 3. MAIN EXECUTION
# ==============================================================================

if __name__ == "__main__":
    # 1. Start the Payment Gateway (Server) in a separate thread
    # `daemon=True` means the thread will exit when the main program exits
    server_thread = threading.Thread(target=gateway_server, daemon=True)
    server_thread.start()
    
    # Give the server a moment to start up and generate keys
    print("[Main] Waiting for server to start...")
    time.sleep(2) 

    # 2. Define our sellers and their transactions
    seller1_transactions = [150, 200, 50]       # 3 transactions
    seller2_transactions = [99, 10, 45, 120]    # 4 transactions
    seller3_transactions = [1000, 500]          # 2 transactions

    # 3. Start each Seller (Client) in its own thread
    t1 = threading.Thread(
        target=run_seller, 
        args=("Seller-A-Electronics", seller1_transactions)
    )
    t2 = threading.Thread(
        target=run_seller, 
        args=("Seller-B-Books", seller2_transactions)
    )
    t3 = threading.Thread(
        target=run_seller,
        args=("Seller-C-Groceries", seller3_transactions)
    )

    t1.start()
    time.sleep(0.5) # Stagger clients slightly
    t2.start()
    time.sleep(0.5)
    t3.start()

    # 4. Wait for all seller threads to complete
    t1.join()
    t2.join()
    t3.join()

    print("\n[Main] All seller simulations complete.")
    print("[Main] The server will continue running. Press Ctrl+C to stop.")
    
    # Keep the main thread alive so the daemon server thread can run
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Main] Exiting program.")