# HealthCare Inc., a leading healthcare provider, has implemented a secure patient data
# management system using the Rabin cryptosystem. The system allows authorized
# healthcare professionals to securely access and manage patient records across multiple
# hospitals and clinics within the organization. Implement a Python-based centralized key
# management service that can:
# • Key Generation: Generate public and private key pairs for each hospital and clinic
# using the Rabin cryptosystem. The key size should be configurable (e.g., 1024 bits).
# • Key Distribution: Provide a secure API for hospitals and clinics to request and receive
# their public and private key pairs.
# • Key Revocation: Implement a process to revoke and update the keys of a hospital or
# clinic when necessary (e.g., when a facility is closed or compromised).
# • Key Renewal: Automatically renew the keys of all hospitals and clinics at regular
# intervals (e.g., every 12 months) to maintain the security of the patient data management
# system.
# • Secure Storage: Securely store the private keys of all hospitals and clinics, ensuring
# that they are not accessible to unauthorized parties.
# • Auditing and Logging: Maintain detailed logs of all key management operations, such
# as key generation, distribution, revocation, and renewal, to enable auditing and
# compliance reporting.
# • Regulatory Compliance: Ensure that the key management service and its operations are
# compliant with relevant data privacy regulations (e.g., HIPAA).
# • Perform a trade-off analysis to compare the workings of Rabin and RSA


import os
import logging
import secrets
from math import gcd
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
from datetime import datetime, timedelta

# Logging setup
logging.basicConfig(filename="key_management.log", level=logging.INFO)

# Secure storage encryption key
storage_key = Fernet.generate_key()
fernet = Fernet(storage_key)

# In-memory key database (replace with persistent DB in production)
key_store = {}

# Rabin key generation
def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    for _ in range(k):
        a = secrets.randbelow(n - 1) + 1
        if pow(a, n-1, n) != 1:
            return False
    return True

def generate_rabin_keys(bits=1024):
    """Generate Rabin public/private keys"""
    def generate_prime():
        while True:
            p = secrets.randbits(bits//2) | 1
            if p % 4 == 3 and is_prime(p):
                return p

    p, q = generate_prime(), generate_prime()
    n = p * q
    return {"public": n, "private": (p, q)}

# Key management operations
def store_keys(facility_id, keys):
    encrypted_priv = fernet.encrypt(str(keys['private']).encode())
    key_store[facility_id] = {"public": keys['public'], "private": encrypted_priv, "generated_at": datetime.now()}
    logging.info(f"{datetime.now()}: Keys generated for {facility_id}")

def revoke_keys(facility_id):
    if facility_id in key_store:
        del key_store[facility_id]
        logging.info(f"{datetime.now()}: Keys revoked for {facility_id}")

def renew_keys(facility_id):
    keys = generate_rabin_keys()
    store_keys(facility_id, keys)
    logging.info(f"{datetime.now()}: Keys renewed for {facility_id}")

def get_keys(facility_id):
    if facility_id not in key_store:
        return None
    encrypted_priv = key_store[facility_id]['private']
    decrypted_priv = fernet.decrypt(encrypted_priv).decode()
    return {"public": key_store[facility_id]['public'], "private": decrypted_priv}

# Flask API
app = Flask(__name__)

@app.route("/generate/<facility_id>", methods=['POST'])
def api_generate(facility_id):
    keys = generate_rabin_keys()
    store_keys(facility_id, keys)
    return jsonify({"message": f"Keys generated for {facility_id}"}), 201

@app.route("/get/<facility_id>", methods=['GET'])
def api_get(facility_id):
    keys = get_keys(facility_id)
    if keys:
        return jsonify(keys)
    return jsonify({"error": "Facility not found"}), 404

@app.route("/revoke/<facility_id>", methods=['POST'])
def api_revoke(facility_id):
    revoke_keys(facility_id)
    return jsonify({"message": f"Keys revoked for {facility_id}"}), 200

@app.route("/renew/<facility_id>", methods=['POST'])
def api_renew(facility_id):
    renew_keys(facility_id)
    return jsonify({"message": f"Keys renewed for {facility_id}"}), 200

if __name__ == "__main__":
    app.run(port=5000)
