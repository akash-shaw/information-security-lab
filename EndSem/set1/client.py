#!/usr/bin/env python3

import socket
import threading
import json
import base64
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from paillier import PaillierKey

# --- Global Configuration ---
HOST = '127.0.0.1'  # localhost
PORT = 65432        # Must match server.py

def run_seller(seller_name, transactions):
    """
    Simulates a single seller connecting to the gateway,
    encrypting transactions, signing the summary, and sending it.
    """
    print(f"[{seller_name}] Starting simulation...")
    
    try:
        # 1. Generate this seller's RSA key pair for signing
        rsa_key = RSA.generate(2048)
        rsa_pub_key_pem = rsa_key.publickey().export_key()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # 2. Connect to the Gateway Server
            s.connect((HOST, PORT))
            
            # 3. Send our RSA Public Key
            s.sendall(rsa_pub_key_pem)
            
            # 4. Receive the Gateway's Paillier Public Key ('n')
            n_str = s.recv(1024).decode('utf-8').strip()
            if not n_str:
                raise ConnectionError("Server disconnected before sending Paillier key")
            try:
                n = int(n_str)
            except ValueError:
                raise ValueError(f"Invalid Paillier key received from server: {n_str}")
            
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
            
            data_to_sign = {
                "seller_name": seller_name,
                "transactions": transactions,
                "encrypted_ciphertexts_str": [str(x) for x in encrypted_txns_ints],
                "total_encrypted_ciphertext_str": str(total_encrypted_int),
            }
            
            # --- 7. Sign the Summary (RSA + SHA-256) ---
            
            # Serialize the data to a canonical JSON string
            data_bytes = json.dumps(data_to_sign, sort_keys=True).encode('utf-8')
            
            # Hash the JSON string
            h = SHA256.new(data_bytes)
            
            # Sign the hash with our RSA private key
            signer = pkcs1_15.new(rsa_key)
            signature = signer.sign(h)
            
            # --- 8. Create Final Payload and Send ---
            
            final_payload = {
                "data": data_to_sign,
                "signature_b64": base64.b64encode(signature).decode('utf-8')
            }
            
            # Send the complete package to the server
            s.sendall(json.dumps(final_payload).encode('utf-8'))
            
            print(f"[{seller_name}] Transaction bundle sent successfully.")

    except Exception as e:
        print(f"[{seller_name}] ERROR: {e}")


if __name__ == "__main__":
    # Define our sellers and their transactions
    seller1_transactions = [150, 200, 50]       # 3 transactions
    seller2_transactions = [99, 10, 45, 120]    # 4 transactions
    seller3_transactions = [1000, 500]          # 2 transactions

    print("[Main] Starting seller simulations...")

    # Start each Seller (Client) in its own thread
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
    time.sleep(0.5) # Stagger clients slightly for cleaner server output
    t2.start()
    time.sleep(0.5)
    t3.start()

    # Wait for all seller threads to complete
    t1.join()
    t2.join()
    t3.join()

    print("[Main] All seller simulations complete.")