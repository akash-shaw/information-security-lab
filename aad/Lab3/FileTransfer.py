import os
import time
import binascii
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from bokeh.plotting import figure, show, output_file
from bokeh.layouts import gridplot
from bokeh.models import HoverTool


def generate_test_file(size_mb):
    """Generate test file of specified size in MB"""
    filename = f"test_file_{size_mb}MB.txt"
    with open(filename, 'wb') as f:
        # Write random data
        for _ in range(size_mb * 1024):  # 1MB = 1024KB
            f.write(get_random_bytes(1024))
    return filename


def rsa_keygen_timed():
    """Generate RSA key pair and measure time"""
    start = time.time()
    key = RSA.generate(2048)
    gen_time = time.time() - start
    return key, gen_time


def ecc_keygen_timed():
    """Generate ECC key pair and measure time"""
    start = time.time()
    key = ECC.generate(curve='secp256r1')
    gen_time = time.time() - start
    return key, gen_time


def rsa_encrypt_file(filename, pub_key):
    """Encrypt file using RSA with AES hybrid encryption"""
    start = time.time()
    
    # Generate AES key
    aes_key = get_random_bytes(32)  # 256-bit AES key
    
    # Encrypt AES key with RSA
    rsa_cipher = PKCS1_OAEP.new(pub_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    
    # Encrypt file with AES
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = aes_cipher.iv
    
    with open(filename, 'rb') as f:
        plaintext = f.read()
    
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = aes_cipher.encrypt(padded_plaintext)
    
    enc_time = time.time() - start
    
    encrypted_data = {
        'encrypted_aes_key': encrypted_aes_key,
        'iv': iv,
        'ciphertext': ciphertext
    }
    
    return encrypted_data, enc_time


def rsa_decrypt_file(encrypted_data, priv_key):
    """Decrypt file using RSA with AES hybrid decryption"""
    start = time.time()
    
    # Decrypt AES key with RSA
    rsa_cipher = PKCS1_OAEP.new(priv_key)
    aes_key = rsa_cipher.decrypt(encrypted_data['encrypted_aes_key'])
    
    # Decrypt file with AES
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, encrypted_data['iv'])
    padded_plaintext = aes_cipher.decrypt(encrypted_data['ciphertext'])
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    dec_time = time.time() - start
    return plaintext, dec_time


def ecc_encrypt_file(filename, pub_key):
    """Encrypt file using ECC with AES hybrid encryption"""
    start = time.time()
    
    # Generate ephemeral key pair
    eph_private = ECC.generate(curve='secp256r1')
    
    # Compute shared secret
    shared_point = pub_key.pointQ * eph_private.d
    shared_x = int(shared_point.x)
    aes_key = SHA256.new(shared_x.to_bytes(32, 'big')).digest()
    
    # Encrypt file with AES
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    
    with open(filename, 'rb') as f:
        plaintext = f.read()
    
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)
    
    enc_time = time.time() - start
    
    encrypted_data = {
        'ephemeral_pub_der': eph_private.public_key().export_key(format='DER'),
        'nonce': aes_cipher.nonce,
        'tag': tag,
        'ciphertext': ciphertext
    }
    
    return encrypted_data, enc_time


def ecc_decrypt_file(encrypted_data, priv_key):
    """Decrypt file using ECC with AES hybrid decryption"""
    start = time.time()
    
    # Import ephemeral public key
    eph_public = ECC.import_key(encrypted_data['ephemeral_pub_der'])
    
    # Compute shared secret
    shared_point = eph_public.pointQ * priv_key.d
    shared_x = int(shared_point.x)
    aes_key = SHA256.new(shared_x.to_bytes(32, 'big')).digest()
    
    # Decrypt file with AES
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=encrypted_data['nonce'])
    plaintext = aes_cipher.decrypt_and_verify(encrypted_data['ciphertext'], encrypted_data['tag'])
    
    dec_time = time.time() - start
    return plaintext, dec_time


def measure_performance(file_sizes):
    """Measure performance for both RSA and ECC"""
    results = {
        'file_sizes': file_sizes,
        'rsa_keygen': [],
        'ecc_keygen': [],
        'rsa_encrypt': [],
        'rsa_decrypt': [],
        'ecc_encrypt': [],
        'ecc_decrypt': [],
        'rsa_key_size': 0,
        'ecc_key_size': 0
    }
    
    print("Performance Testing - RSA vs ECC File Transfer")
    print("=" * 50)
    
    # Generate keys once
    rsa_key, rsa_keygen_time = rsa_keygen_timed()
    ecc_key, ecc_keygen_time = ecc_keygen_timed()
    
    # Calculate key sizes
    results['rsa_key_size'] = len(rsa_key.export_key('DER'))
    results['ecc_key_size'] = len(ecc_key.export_key(format='DER'))
    
    print(f"RSA Key Generation Time: {rsa_keygen_time:.4f} seconds")
    print(f"ECC Key Generation Time: {ecc_keygen_time:.4f} seconds")
    print(f"RSA Key Size: {results['rsa_key_size']} bytes")
    print(f"ECC Key Size: {results['ecc_key_size']} bytes")
    print()
    
    for size in file_sizes:
        print(f"Testing {size}MB file...")
        
        # Generate test file
        filename = generate_test_file(size)
        
        try:
            # RSA performance
            rsa_pub = rsa_key.publickey()
            encrypted_rsa, rsa_enc_time = rsa_encrypt_file(filename, rsa_pub)
            decrypted_rsa, rsa_dec_time = rsa_decrypt_file(encrypted_rsa, rsa_key)
            
            # ECC performance
            ecc_pub = ecc_key.public_key()
            encrypted_ecc, ecc_enc_time = ecc_encrypt_file(filename, ecc_pub)
            decrypted_ecc, ecc_dec_time = ecc_decrypt_file(encrypted_ecc, ecc_key)
            
            # Store results
            results['rsa_keygen'].append(rsa_keygen_time)
            results['ecc_keygen'].append(ecc_keygen_time)
            results['rsa_encrypt'].append(rsa_enc_time)
            results['rsa_decrypt'].append(rsa_dec_time)
            results['ecc_encrypt'].append(ecc_enc_time)
            results['ecc_decrypt'].append(ecc_dec_time)
            
            print(f"  RSA - Encrypt: {rsa_enc_time:.4f}s, Decrypt: {rsa_dec_time:.4f}s")
            print(f"  ECC - Encrypt: {ecc_enc_time:.4f}s, Decrypt: {ecc_dec_time:.4f}s")
            
        finally:
            # Clean up test file
            if os.path.exists(filename):
                os.remove(filename)
        
        print()
    
    return results


def create_performance_graphs(results):
    """Create performance comparison graphs using Bokeh"""
    output_file("file_transfer_performance.html")
    
    file_sizes = results['file_sizes']
    
    # Encryption time comparison
    p1 = figure(title="Encryption Time Comparison", x_axis_label="File Size (MB)", 
                y_axis_label="Time (seconds)", width=400, height=300)
    p1.line(file_sizes, results['rsa_encrypt'], legend_label="RSA", line_color="red", line_width=2)
    p1.circle(file_sizes, results['rsa_encrypt'], color="red", size=6)
    p1.line(file_sizes, results['ecc_encrypt'], legend_label="ECC", line_color="blue", line_width=2)
    p1.circle(file_sizes, results['ecc_encrypt'], color="blue", size=6)
    p1.legend.location = "top_left"
    
    # Decryption time comparison
    p2 = figure(title="Decryption Time Comparison", x_axis_label="File Size (MB)", 
                y_axis_label="Time (seconds)", width=400, height=300)
    p2.line(file_sizes, results['rsa_decrypt'], legend_label="RSA", line_color="red", line_width=2)
    p2.circle(file_sizes, results['rsa_decrypt'], color="red", size=6)
    p2.line(file_sizes, results['ecc_decrypt'], legend_label="ECC", line_color="blue", line_width=2)
    p2.circle(file_sizes, results['ecc_decrypt'], color="blue", size=6)
    p2.legend.location = "top_left"
    
    # Key generation comparison
    p3 = figure(title="Key Generation Time", x_axis_label="Algorithm", 
                y_axis_label="Time (seconds)", width=400, height=300,
                x_range=["RSA", "ECC"])
    p3.vbar(x=["RSA", "ECC"], top=[results['rsa_keygen'][0], results['ecc_keygen'][0]], 
            width=0.5, color=["red", "blue"])
    
    # Key size comparison
    p4 = figure(title="Key Size Comparison", x_axis_label="Algorithm", 
                y_axis_label="Size (bytes)", width=400, height=300,
                x_range=["RSA", "ECC"])
    p4.vbar(x=["RSA", "ECC"], top=[results['rsa_key_size'], results['ecc_key_size']], 
            width=0.5, color=["red", "blue"])
    
    # Create grid layout
    grid = gridplot([[p1, p2], [p3, p4]])
    show(grid)


def print_security_analysis():
    """Print security analysis and comparison"""
    print("\nSecurity Analysis - RSA vs ECC")
    print("=" * 50)
    print("RSA (2048-bit):")
    print("  • Security Level: ~112 bits")
    print("  • Key Size: Large (2048+ bits)")
    print("  • Resistance: Integer factorization problem")
    print("  • Quantum Threat: Vulnerable to Shor's algorithm")
    print("  • Computational Overhead: High for large keys")
    print()
    print("ECC (secp256r1):")
    print("  • Security Level: ~128 bits")
    print("  • Key Size: Small (256 bits)")
    print("  • Resistance: Elliptic curve discrete logarithm problem")
    print("  • Quantum Threat: Vulnerable to modified Shor's algorithm")
    print("  • Computational Overhead: Lower than equivalent RSA")
    print()
    print("Summary:")
    print("  • ECC provides equivalent security with smaller keys")
    print("  • ECC is more efficient for mobile/embedded systems")
    print("  • RSA is more widely supported and established")
    print("  • Both require post-quantum alternatives for future security")


def main():
    """Main function to run the file transfer comparison"""
    file_sizes = [1, 5, 10]  # MB
    
    print("Secure File Transfer System - RSA vs ECC Comparison")
    print("=" * 60)
    
    # Measure performance
    results = measure_performance(file_sizes)
    
    # Create performance graphs
    create_performance_graphs(results)
    
    # Print security analysis
    print_security_analysis()
    
    print(f"\nPerformance graphs saved to: file_transfer_performance.html")
    print("Open the HTML file in your browser to view the interactive graphs.")


if __name__ == '__main__':
    main()
