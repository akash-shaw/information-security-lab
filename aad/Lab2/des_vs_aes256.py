import time
import numpy as np
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from bokeh.plotting import figure, show
from bokeh.models import HoverTool
from bokeh.layouts import column
from bokeh.palettes import Category10

def aes_cipher(key):
    return AES.new(key.encode('utf-8'), AES.MODE_ECB)

def aes_en(ptext, key):
    cipher = aes_cipher(key)
    ptext = pad(ptext.encode('utf-8'), AES.block_size)
    return cipher.encrypt(ptext)

def aes_de(ctext, key):
    cipher = aes_cipher(key)
    decrypted = cipher.decrypt(ctext)
    return unpad(decrypted, AES.block_size).decode('utf-8')

def aes256_pad_key(key):
    return key.ljust(32)[:32]

def des_cipher(key):
    return DES.new(key.encode('utf-8'), DES.MODE_ECB)

def des_en(ptext, key):
    cipher = des_cipher(key)
    ptext = pad(ptext.encode('utf-8'), DES.block_size)
    return cipher.encrypt(ptext)

def des_de(ctext, key):
    cipher = des_cipher(key)
    decrypted = cipher.decrypt(ctext)
    return unpad(decrypted, DES.block_size).decode('utf-8')

def des_pad_key(key):
    return key.ljust(8)[:8]

def time_encryption_progressive(encrypt_func, plaintext, key, max_iterations=1000):
    """Time encryption across different iteration counts"""
    iteration_counts = np.logspace(1, np.log10(max_iterations), 10, dtype=int)
    times_per_iteration = []

    for iterations in iteration_counts:
        start_time = time.time()
        for _ in range(iterations):
            encrypt_func(plaintext, key)
        end_time = time.time()
        total_time = end_time - start_time
        times_per_iteration.append(total_time / iterations)

    return iteration_counts, times_per_iteration

def time_decryption_progressive(decrypt_func, ciphertext, key, max_iterations=1000):
    """Time decryption across different iteration counts"""
    iteration_counts = np.logspace(1, np.log10(max_iterations), 10, dtype=int)
    times_per_iteration = []

    for iterations in iteration_counts:
        start_time = time.time()
        for _ in range(iterations):
            decrypt_func(ciphertext, key)
        end_time = time.time()
        total_time = end_time - start_time
        times_per_iteration.append(total_time / iterations)

    return iteration_counts, times_per_iteration

def benchmark_ciphers(plaintext, raw_key, max_iterations=1000):
    # Prepare keys
    aes_key = aes256_pad_key(raw_key)
    des_key = des_pad_key(raw_key)

    # Get ciphertexts for decryption timing
    aes_ciphertext = aes_en(plaintext, aes_key)
    des_ciphertext = des_en(plaintext, des_key)

    # Time encryption progressively
    aes_enc_iterations, aes_enc_times = time_encryption_progressive(aes_en, plaintext, aes_key, max_iterations)
    des_enc_iterations, des_enc_times = time_encryption_progressive(des_en, plaintext, des_key, max_iterations)

    # Time decryption progressively
    aes_dec_iterations, aes_dec_times = time_decryption_progressive(aes_de, aes_ciphertext, aes_key, max_iterations)
    des_dec_iterations, des_dec_times = time_decryption_progressive(des_de, des_ciphertext, des_key, max_iterations)

    return {
        'aes_enc_iterations': aes_enc_iterations,
        'aes_enc_times': aes_enc_times,
        'des_enc_iterations': des_enc_iterations,
        'des_enc_times': des_enc_times,
        'aes_dec_iterations': aes_dec_iterations,
        'aes_dec_times': aes_dec_times,
        'des_dec_iterations': des_dec_iterations,
        'des_dec_times': des_dec_times
    }

def create_plot(title, plaintext_length):
    return figure(
        title=f"{title}\nPlaintext length: {plaintext_length} chars",
        x_axis_label="Number of Iterations",
        y_axis_label="Time per Operation (seconds)",
        x_axis_type="log",
        y_axis_type="log",
        width=800,
        height=400,
        background_fill_color="#fafafa",
        border_fill_color="whitesmoke"
    )

def add_line_and_markers(plot, x_data, y_data, color, label):
    plot.line(x_data, y_data, line_width=3, color=color, alpha=0.8, legend_label=label)
    plot.scatter(x_data, y_data, size=8, color=color, alpha=0.8)

def plot_results(results, plaintext_length):
    colors = Category10[4]

    # Create plots
    p1 = create_plot("Encryption Performance: Time per Operation", plaintext_length)
    p2 = create_plot("Decryption Performance: Time per Operation", plaintext_length)

    # Add data to plots
    add_line_and_markers(p1, results['aes_enc_iterations'], results['aes_enc_times'], colors[0], "AES-256 Encryption")
    add_line_and_markers(p1, results['des_enc_iterations'], results['des_enc_times'], colors[1], "DES Encryption")
    add_line_and_markers(p2, results['aes_dec_iterations'], results['aes_dec_times'], colors[2], "AES-256 Decryption")
    add_line_and_markers(p2, results['des_dec_iterations'], results['des_dec_times'], colors[3], "DES Decryption")

    # Add hover tools and styling
    hover = HoverTool(tooltips=[("Algorithm", "@legend_label"), ("Iterations", "@x"), ("Time per Op", "@y{0.0000000} sec")])

    for p in [p1, p2]:
        p.add_tools(hover)
        p.legend.location = "top_right"
        p.legend.click_policy = "hide"
        p.legend.background_fill_alpha = 0.8
        p.grid.grid_line_alpha = 0.3

    show(column(p1, p2))

def main():
    print("AES-256 vs DES Performance Comparison")
    print("=====================================")

    plaintext = input("Enter plaintext: ")
    key = input("Enter key: ")
    max_iterations = int(input("Enter maximum number of iterations (default 1000): ") or "1000")

    print(f"\nBenchmarking across iteration ranges up to {max_iterations}...")
    results = benchmark_ciphers(plaintext, key, max_iterations)

    # Calculate average times for comparison
    avg_aes_enc = np.mean(results['aes_enc_times'])
    avg_des_enc = np.mean(results['des_enc_times'])
    avg_aes_dec = np.mean(results['aes_dec_times'])
    avg_des_dec = np.mean(results['des_dec_times'])

    print("\nAverage Results (time per operation):")
    print(f"AES-256 Encryption: {avg_aes_enc:.8f} seconds")
    print(f"DES Encryption:     {avg_des_enc:.8f} seconds")
    print(f"AES-256 Decryption: {avg_aes_dec:.8f} seconds")
    print(f"DES Decryption:     {avg_des_dec:.8f} seconds")

    print("\nSpeed comparison:")
    if avg_aes_enc < avg_des_enc:
        ratio = avg_des_enc / avg_aes_enc
        print(f"AES-256 encryption is {ratio:.2f}x faster than DES")
    else:
        ratio = avg_aes_enc / avg_des_enc
        print(f"DES encryption is {ratio:.2f}x faster than AES-256")

    plot_results(results, len(plaintext))

if __name__ == '__main__':
    main()
