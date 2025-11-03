#!/usr/bin/env python3

"""
Payment Gateway Server
This script implements a secure payment gateway that:
1. Accepts connections from multiple sellers
2. Uses Paillier homomorphic encryption for transaction amounts
3. Verifies digital signatures on transaction bundles
4. Processes and validates transaction summaries
"""

import socket
import threading
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from paillier import PaillierKey

# --- Global Configuration ---
HOST = '127.0.0.1'  # localhost
PORT = 65432        # Port number for the server

# Global Variables
# -----------------------------
# The server's Paillier key pair - shared across all seller handler threads
server_paillier_key = None

# Thread-safe lock for ensuring clean console output when multiple sellers connect
print_lock = threading.Lock()

def handle_seller(conn, addr):
    """
    Handles a single connection from a seller in a separate thread.
    
    This function:
    1. Receives the seller's RSA public key for signature verification
    2. Sends our Paillier public key for transaction encryption
    3. Receives and verifies the signed transaction bundle
    4. Decrypts and validates all transactions
    5. Outputs a complete transaction summary
    
    Args:
        conn: Socket connection to the seller
        addr: Address information of the seller
    """
    global server_paillier_key
    
    print(f"[Gateway] New connection from {addr}")
    client_rsa_pub = None
    
    try:
        # Step 1: Key Exchange
        # -----------------------------
        # First, receive the seller's RSA public key
        # This will be used to verify their digital signature
        client_rsa_pem = conn.recv(1024)
        if not client_rsa_pem:
            raise ConnectionError("Client disconnected before sending RSA key")
        client_rsa_pub = RSA.import_key(client_rsa_pem)
        
        # Send our Paillier public key (just 'n')
        # The seller needs this to encrypt their transaction amounts
        conn.sendall(str(server_paillier_key.n).encode('utf-8'))
        
        # Step 2: Receive Transaction Data
        # -----------------------------
        # Receive the complete transaction bundle
        # Using larger buffer (4096) to handle multiple transactions
        payload_bytes = conn.recv(4096)
        if not payload_bytes:
            raise ConnectionError("Client disconnected before sending payload")
            
        # Parse the JSON payload
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        # Extract signed data and signature
        data_signed = payload['data']          # The actual transaction data
        signature_b64 = payload['signature_b64']  # Base64 encoded signature
        signature = base64.b64decode(signature_b64)  # Convert to binary

        # --- 4. Digital Signature Verification (RSA + SHA-256) ---
        
        # We must re-serialize the data *exactly* as the client did
        data_bytes = json.dumps(data_signed, sort_keys=True).encode('utf-8')
        h = SHA256.new(data_bytes)
        
        verification_result = ""
        try:
            pkcs1_15.new(client_rsa_pub).verify(h, signature)
            verification_result = "SUCCESS"
        except (ValueError, TypeError):
            verification_result = "FAILED - SIGNATURE INVALID"

        # --- 5. Paillier Homomorphic Decryption ---
        
        # Decrypt individual transactions
        decrypted_individuals = []
        for c_str in data_signed['encrypted_ciphertexts_str']:
            c_int = int(c_str)
            decrypted_individuals.append(server_paillier_key.decrypt(c_int))

        # Decrypt the homomorphically added total
        total_c_int = int(data_signed['total_encrypted_ciphertext_str'])
        total_decrypted = server_paillier_key.decrypt(total_c_int)

        # --- 6. Output Final Transaction Summary ---
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
                print(f"  Txn {i+1} Encrypted:   {data_signed['encrypted_ciphertexts_str'][i][:40]}...")
                print(f"  Txn {i+1} Decrypted:   {decrypted_individuals[i]}")
                print("  ---")
            
            print("** 3. Homomorphic Total **")
            print(f"  Total Encrypted (Homomorphic Sum): {data_signed['total_encrypted_ciphertext_str'][:40]}...")
            print(f"  Total Decrypted (from Sum):      {total_decrypted}")
            
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
    Main server function that:
    1. Generates the server's Paillier key pair for homomorphic encryption
    2. Sets up a TCP server socket
    3. Listens for incoming seller connections
    4. Spawns a new thread for each connected seller
    
    The server uses threading to handle multiple sellers simultaneously.
    Each seller gets their own thread running the handle_seller function.
    """
    global server_paillier_key
    
    # Step 1: Generate Paillier Keys
    # -----------------------------
    # We use 1024-bit keys for this demo (2048+ recommended for production)
    print("[Gateway] Generating 1024-bit Paillier key pair...")
    server_paillier_key = PaillierKey(1024)
    print("[Gateway] Paillier key pair generated.")
    
    # Step 2: Set Up Server Socket
    # -----------------------------
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind to host and port
        s.bind((HOST, PORT))
        # Listen for connections (queue up to 5)
        s.listen(5)
        print(f"[Gateway] Payment Gateway Server listening on {HOST}:{PORT}")
        
        # Step 3: Main Server Loop
        # -----------------------------
        try:
            while True:
                # Wait for a seller to connect
                conn, addr = s.accept()
                
                # Start a new thread to handle this seller
                # This allows us to handle multiple sellers simultaneously
                handler_thread = threading.Thread(
                    target=handle_seller, 
                    args=(conn, addr)
                )
                handler_thread.start()
                
        except KeyboardInterrupt:
            print("\n[Gateway] Shutting down server...")
        finally:
            s.close()

if __name__ == "__main__":
    gateway_server()