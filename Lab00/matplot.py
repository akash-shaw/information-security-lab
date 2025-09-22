# Python Matplotlib Teaching Script
# Author: ChatGPT
# Purpose: Teach Matplotlib library in Python with detailed explanations

########################################
# 1. Introduction to Matplotlib
########################################
# Matplotlib is a popular Python library for creating static, animated, and interactive plots.
# The main module for plotting is pyplot.

import matplotlib.pyplot as plt
import numpy as np  # NumPy is often used for numerical data in plots

########################################
# 2. Basic Line Plot
########################################

# Simple x and y data
x = np.array([0, 1, 2, 3, 4, 5])
y = np.array([0, 1, 4, 9, 16, 25])

plt.plot(x, y)  # plot y vs x
plt.title("Basic Line Plot")  # plot title
plt.xlabel("X-axis")  # x-axis label
plt.ylabel("Y-axis")  # y-axis label
plt.grid(True)  # show grid
plt.show()  # display the plot

########################################
# 3. Multiple Lines
########################################

y2 = np.array([0, 1, 8, 27, 64, 125])
plt.plot(x, y, label="y = x^2", color="blue", marker='o')  # add marker
plt.plot(x, y2, label="y = x^3", color="red", linestyle='--')  # dashed line
plt.title("Multiple Lines")
plt.xlabel("X-axis")
plt.ylabel("Y-axis")
plt.legend()  # show legend
plt.grid(True)
plt.show()

########################################
# 4. Scatter Plot
########################################

x = np.random.rand(50)  # 50 random x values
y = np.random.rand(50)  # 50 random y values

plt.scatter(x, y, color='green', marker='x')
plt.title("Scatter Plot")
plt.xlabel("X-axis")
plt.ylabel("Y-axis")
plt.grid(True)
plt.show()

########################################
# 5. Bar Chart
########################################

categories = ['A', 'B', 'C', 'D']
values = [10, 24, 36, 18]

plt.bar(categories, values, color='orange')
plt.title("Bar Chart")
plt.xlabel("Categories")
plt.ylabel("Values")
plt.show()

# Horizontal Bar Chart
plt.barh(categories, values, color='purple')
plt.title("Horizontal Bar Chart")
plt.xlabel("Values")
plt.ylabel("Categories")
plt.show()

########################################
# 6. Histogram
########################################

data = np.random.randn(1000)  # generate 1000 random numbers from normal distribution
plt.hist(data, bins=20, color='blue', edgecolor='black')
plt.title("Histogram")
plt.xlabel("Value")
plt.ylabel("Frequency")
plt.show()

########################################
# 7. Pie Chart
########################################

sizes = [20, 30, 25, 25]
labels = ['Python', 'Java', 'C++', 'JavaScript']
colors = ['gold', 'lightblue', 'lightgreen', 'pink']

plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
plt.title("Pie Chart")
plt.show()

########################################
# 8. Subplots
########################################

x = np.linspace(0, 10, 100)  # 100 points between 0 and 10
y1 = np.sin(x)
y2 = np.cos(x)

# Create 2 subplots: 1 row, 2 columns
plt.subplot(1, 2, 1)  # row 1, col 2, subplot 1
plt.plot(x, y1, color='blue')
plt.title("Sine Wave")

plt.subplot(1, 2, 2)  # subplot 2
plt.plot(x, y2, color='red')
plt.title("Cosine Wave")

plt.tight_layout()  # adjust spacing
plt.show()

########################################
# 9. Customization
########################################

plt.plot(x, y1, label="Sine", color='green', linewidth=2, linestyle='-', marker='o', markersize=4)
plt.plot(x, y2, label="Cosine", color='orange', linewidth=2, linestyle='--', marker='x', markersize=4)
plt.title("Customized Plot")
plt.xlabel("X-axis")
plt.ylabel("Y-axis")
plt.legend()
plt.grid(True)
plt.xlim(0, 10)  # limit x-axis
plt.ylim(-1.5, 1.5)  # limit y-axis
plt.show()

########################################
# 10. Advanced Plotting: Filling, Annotation
########################################

plt.plot(x, y1, color='blue', label='Sine')
plt.fill_between(x, y1, color='lightblue', alpha=0.5)  # fill under curve
plt.title("Filled Plot")
plt.xlabel("X-axis")
plt.ylabel("Y-axis")
plt.legend()
plt.grid(True)

# Annotate a point
plt.annotate('Peak', xy=(np.pi/2, 1), xytext=(2, 0.8),
             arrowprops=dict(facecolor='black', shrink=0.05))
plt.show()

########################################
# 11. Saving Plots
########################################

plt.plot(x, y1)
plt.title("Save Plot Example")
plt.savefig("sine_wave.png")  # save plot as PNG file
plt.savefig("sine_wave.pdf")  # save plot as PDF
plt.close()  # close the plot

########################################
# 12. Summary
########################################
print("Matplotlib concepts covered: Line plot, multiple lines, scatter, bar chart, histogram, pie chart, subplots, customization, annotation, saving plots.")
