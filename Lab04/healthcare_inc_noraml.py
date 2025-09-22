import os, json, time, logging
from sympy import nextprime
import secrets

# -------------------------------
# Setup Logging
logging.basicConfig(filename='key_management.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# -------------------------------
# Rabin Key Generation
def generate_rabin_key(bits=1024):
    """Generates a Rabin key pair (p, q, n)"""
    p = nextprime(secrets.randbits(bits//2))
    while p % 4 != 3:
        p = nextprime(p)
    q = nextprime(secrets.randbits(bits//2))
    while q % 4 != 3 or q == p:
        q = nextprime(secrets.randbits(bits//2))
    n = p * q
    return {'p': p, 'q': q, 'n': n}

# -------------------------------
# Centralized Key Storage
class KeyStore:
    def __init__(self, filename="keys.json"):
        self.filename = filename
        if not os.path.exists(filename):
            with open(filename, "w") as f:
                json.dump({}, f)
    
    def load(self):
        with open(self.filename, "r") as f:
            return json.load(f)
    
    def save(self, data):
        with open(self.filename, "w") as f:
            json.dump(data, f)
    
    def add_key(self, hospital_id, keypair):
        data = self.load()
        data[hospital_id] = {
            'keypair': keypair,
            'revoked': False,
            'created_at': time.time()
        }
        self.save(data)
        logging.info(f"Key generated for {hospital_id}")
    
    def revoke_key(self, hospital_id):
        data = self.load()
        if hospital_id in data:
            data[hospital_id]['revoked'] = True
            self.save(data)
            logging.info(f"Key revoked for {hospital_id}")
    
    def renew_key(self, hospital_id, bits=1024):
        data = self.load()
        if hospital_id in data:
            keypair = generate_rabin_key(bits)
            data[hospital_id]['keypair'] = keypair
            data[hospital_id]['revoked'] = False
            data[hospital_id]['created_at'] = time.time()
            self.save(data)
            logging.info(f"Key renewed for {hospital_id}")
    
    def get_public_key(self, hospital_id):
        data = self.load()
        if hospital_id in data and not data[hospital_id]['revoked']:
            return data[hospital_id]['keypair']['n']
        return None

# -------------------------------
# Example Usage
store = KeyStore()

# Generate keys for Hospital A and Clinic B
store.add_key("HospitalA", generate_rabin_key(1024))
store.add_key("ClinicB", generate_rabin_key(1024))

# Fetch public key
pub_key = store.get_public_key("HospitalA")
print(f"HospitalA public key (n): {pub_key}")

# Revoke and renew keys
store.revoke_key("ClinicB")
store.renew_key("ClinicB", 1024)
