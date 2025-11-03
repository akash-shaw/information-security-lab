from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
import time
from bokeh.plotting import figure, show, output_file
from bokeh.models import HoverTool, ColumnDataSource
from bokeh.layouts import column, row
import bokeh.palettes as bp

def pad_key(key, length):
    return key.ljust(length)[:length].encode('utf-8')

def encrypt_with_timing(cipher_func, ptext, key, *args):
    # Use more precise timing for microsecond measurements
    start_time = time.perf_counter()
    result = cipher_func(ptext, key, *args)
    end_time = time.perf_counter()
    return result, end_time - start_time

def des_encrypt(ptext, key, mode):
    key = pad_key(key, 8)
    cipher = DES.new(key, mode)
    padded_text = pad(ptext.encode('utf-8'), DES.block_size)
    return cipher.encrypt(padded_text)

def des3_encrypt(ptext, key, key_size, mode):
    if key_size == 128:
        key = pad_key(key, 16)
    elif key_size == 192:
        key = pad_key(key, 24)
    else:  # 256 bit uses 192 bit key (DES3 limitation)
        key = pad_key(key, 24)

    cipher = DES3.new(key, mode)
    padded_text = pad(ptext.encode('utf-8'), DES3.block_size)
    return cipher.encrypt(padded_text)

def aes_encrypt(ptext, key, key_size, mode):
    if key_size == 128:
        key = pad_key(key, 16)
    elif key_size == 192:
        key = pad_key(key, 24)
    else:  # 256
        key = pad_key(key, 32)

    cipher = AES.new(key, mode)
    padded_text = pad(ptext.encode('utf-8'), AES.block_size)
    return cipher.encrypt(padded_text)

def des_128(ptext, key, mode=DES.MODE_ECB):
    return des_encrypt(ptext, key, mode)

def des_192(ptext, key, mode=DES3.MODE_ECB):
    return des3_encrypt(ptext, key, 192, mode)

def des_256(ptext, key, mode=DES3.MODE_ECB):
    return des3_encrypt(ptext, key, 256, mode)

def aes_128(ptext, key, mode=AES.MODE_ECB):
    return aes_encrypt(ptext, key, 128, mode)

def aes_192(ptext, key, mode=AES.MODE_ECB):
    return aes_encrypt(ptext, key, 192, mode)

def aes_256(ptext, key, mode=AES.MODE_ECB):
    return aes_encrypt(ptext, key, 256, mode)

def bokeh_graph(timing_data):
    output_file("encryption_performance.html")

    from bokeh.models import LinearColorMapper, ColorBar, BasicTicker, PrintfTickFormatter
    from bokeh.transform import transform
    import math

    algorithms = list(timing_data.keys())
    messages = [f"Msg {i+1}" for i in range(len(next(iter(timing_data.values()))))]

    # Convert all times to microseconds for better visibility
    def to_microseconds(seconds):
        return seconds * 1_000_000

    # Chart 2: Performance variability - Box plot style using circles and lines
    p2 = figure(x_range=algorithms, title="Performance Distribution Across Messages",
                toolbar_location=None, tools="", width=800, height=400)

    for i, algo_name in enumerate(algorithms):
        times_us = [to_microseconds(t) for t in timing_data[algo_name]]

        # Calculate statistics
        mean_time = sum(times_us) / len(times_us)
        min_time = min(times_us)
        max_time = max(times_us)

        # Plot range line
        p2.line([i, i], [min_time, max_time], line_width=2, color=colors[i], alpha=0.6)

        # Plot individual points
        y_positions = times_us
        x_positions = [i + (j - 2) * 0.1 for j in range(len(times_us))]  # Spread points horizontally
        p2.circle(x_positions, y_positions, size=8, color=colors[i], alpha=0.8)

        # Plot mean as a diamond
        p2.diamond([i], [mean_time], size=12, color=colors[i], line_color="black", line_width=1)

    p2.xaxis.major_label_orientation = 45
    p2.yaxis.axis_label = "Execution Time (microseconds)"
    p2.xaxis.axis_label = "Encryption Algorithm"
    p2.xaxis.ticker = BasicTicker()
    p2.xaxis.formatter = PrintfTickFormatter(format="%s")

    hover2 = HoverTool(tooltips=[("Time (μs)", "@y{0.00}")], mode='vline')
    p2.add_tools(hover2)

    # Chart 4: Relative performance comparison (normalized to fastest)
    p4 = figure(x_range=algorithms, title="Relative Performance (Normalized to Fastest Algorithm)",
                toolbar_location=None, tools="", width=800, height=400)

    # Find the fastest average time
    fastest_avg = min(avg_times)
    relative_times = [avg / fastest_avg for avg in avg_times]

    bars4 = p4.vbar(x=algorithms, top=relative_times, width=0.6, color=colors, alpha=0.8)

    # Add reference line at 1.0
    p4.line([-0.5, len(algorithms)-0.5], [1, 1], line_dash="dashed", line_width=2, color="red", alpha=0.7)

    p4.xaxis.major_label_orientation = 45
    p4.yaxis.axis_label = "Relative Performance (1.0 = fastest)"
    p4.xaxis.axis_label = "Encryption Algorithm"

    hover4 = HoverTool(tooltips=[("Algorithm", "@x"), ("Relative Speed", "@top{0.00}x")], renderers=[bars4])
    p4.add_tools(hover4)

    # Layout all charts
    layout = column(
        row(p2),
        row(p4)
    )

    show(layout)

def main():
    print("The AES/DES Encryptor with Performance Analysis")

    # Get exactly 5 messages from user
    messages = []
    print("\nEnter exactly 5 messages to encrypt:")
    for i in range(5):
        while True:
            message = input(f"Message {i+1}: ")
            if message.strip():  # Only accept non-empty messages
                messages.append(message)
                break
            else:
                print("Please enter a non-empty message.")

    key = input("\nEnter key: ")

    # Define algorithms to test (using ECB mode only)
    algorithms = [
        ('DES', des_128, DES.MODE_ECB),
        ('DES3-192', des_192, DES3.MODE_ECB),
        ('AES-128', aes_128, AES.MODE_ECB),
        ('AES-192', aes_192, AES.MODE_ECB),
        ('AES-256', aes_256, AES.MODE_ECB)
    ]

    timing_data = {}

    print("\nEncrypting messages and measuring performance...\n")

    # Run each message through each algorithm multiple times for better precision
    for algo_name, algo_func, mode in algorithms:
        timing_data[algo_name] = []
        print(f"=== {algo_name} ===")

        for i, message in enumerate(messages):
            print(f"Message {i+1}: {message[:30]}...")

            # Run multiple times and take the best time to reduce noise
            best_time = float('inf')
            for _ in range(10):  # 10 runs for better precision
                ctext, exec_time = encrypt_with_timing(algo_func, message, key, mode)
                best_time = min(best_time, exec_time)

            print(f"{algo_name}: {best_time:.8f}s ({best_time*1000000:.2f}μs)")
            timing_data[algo_name].append(best_time)

        print()

    # Generate performance graphs
    print("Generating performance visualization...")
    bokeh_graph(timing_data)
    print("Performance graphs saved to 'encryption_performance.html'")

if __name__ == '__main__':
    main()
