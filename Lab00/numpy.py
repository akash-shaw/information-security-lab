# Python NumPy Teaching Script
# Author: ChatGPT
# Purpose: Teach NumPy library in Python with detailed explanations

########################################
# 1. Introduction to NumPy
########################################
# NumPy (Numerical Python) is a powerful library for numerical computations
# It provides multi-dimensional arrays (ndarray) and functions to operate on them efficiently

import numpy as np  # Import NumPy library

########################################
# 2. Creating Arrays
########################################

# 2.1 1D Array
arr1 = np.array([1, 2, 3, 4, 5])
print("1D Array:", arr1)
print("Type:", type(arr1))
print("Shape:", arr1.shape)  # (5,)
print("Data type:", arr1.dtype)

# 2.2 2D Array (Matrix)
arr2 = np.array([[1, 2, 3], [4, 5, 6]])
print("\n2D Array:\n", arr2)
print("Shape:", arr2.shape)  # (2, 3)
print("Number of dimensions:", arr2.ndim)

# 2.3 3D Array
arr3 = np.array([[[1, 2], [3, 4]], [[5, 6], [7, 8]]])
print("\n3D Array:\n", arr3)
print("Shape:", arr3.shape)  # (2, 2, 2)

########################################
# 3. Array Creation Functions
########################################

# zeros, ones, full
zeros = np.zeros((2,3))  # 2x3 array of zeros
ones = np.ones((3,2))    # 3x2 array of ones
full = np.full((2,2), 7) # 2x2 array filled with 7

print("\nZeros:\n", zeros)
print("Ones:\n", ones)
print("Full:\n", full)

# arange and linspace
arr_arange = np.arange(0, 10, 2)  # start=0, stop=10, step=2
arr_linspace = np.linspace(0, 1, 5)  # 5 equally spaced numbers between 0 and 1

print("\nArange:", arr_arange)
print("Linspace:", arr_linspace)

# random numbers
rand = np.random.rand(3,3)  # random numbers between 0 and 1
rand_int = np.random.randint(1, 10, size=(2,3))  # random integers between 1-10
print("\nRandom float array:\n", rand)
print("Random integer array:\n", rand_int)

########################################
# 4. Array Operations
########################################

a = np.array([1, 2, 3])
b = np.array([4, 5, 6])

# 4.1 Element-wise operations
print("\na + b =", a + b)
print("a - b =", a - b)
print("a * b =", a * b)
print("a / b =", a / b)
print("a ** 2 =", a ** 2)

# 4.2 Universal Functions (ufunc)
print("\nSquare root of a:", np.sqrt(a))
print("Exponential of a:", np.exp(a))
print("Sine of a:", np.sin(a))

########################################
# 5. Indexing and Slicing
########################################

arr = np.array([10, 20, 30, 40, 50])
print("\nArray:", arr)
print("First element:", arr[0])
print("Last element:", arr[-1])
print("Slice arr[1:4]:", arr[1:4])  # 2nd to 4th element

# 2D Array slicing
matrix = np.array([[1,2,3],[4,5,6],[7,8,9]])
print("\nMatrix:\n", matrix)
print("First row:", matrix[0])
print("Second column:", matrix[:,1])
print("Submatrix:\n", matrix[0:2, 1:3])  # rows 0-1, cols 1-2

########################################
# 6. Boolean Indexing
########################################

arr = np.array([10, 15, 20, 25, 30])
bool_idx = arr > 20
print("\nBoolean Indexing:", bool_idx)
print("Elements greater than 20:", arr[bool_idx])

# Or directly
print("Elements > 20:", arr[arr > 20])

########################################
# 7. Shape Manipulation
########################################

arr = np.arange(1, 10)  # 1D array
print("\nOriginal arr:", arr)

# Reshape
arr2d = arr.reshape(3,3)
print("Reshaped 3x3:\n", arr2d)

# Flatten
flattened = arr2d.flatten()
print("Flattened array:", flattened)

# Transpose
print("Transposed:\n", arr2d.T)

########################################
# 8. Stacking Arrays
########################################

a = np.array([1,2,3])
b = np.array([4,5,6])

# Vertical stack
vstack = np.vstack((a,b))
print("\nVertical Stack:\n", vstack)

# Horizontal stack
hstack = np.hstack((a,b))
print("Horizontal Stack:", hstack)

########################################
# 9. Mathematical and Statistical Operations
########################################

arr = np.array([[1,2,3],[4,5,6]])

print("\nSum of all elements:", np.sum(arr))
print("Sum along columns:", np.sum(arr, axis=0))
print("Sum along rows:", np.sum(arr, axis=1))

print("Mean:", np.mean(arr))
print("Standard Deviation:", np.std(arr))
print("Minimum:", np.min(arr))
print("Maximum:", np.max(arr))

########################################
# 10. Broadcasting
########################################

# Adding a 1D array to 2D array
matrix = np.array([[1,2,3],[4,5,6]])
row = np.array([10,20,30])
result = matrix + row  # row is broadcasted to each row
print("\nMatrix + Row (Broadcasting):\n", result)

########################################
# 11. Linear Algebra
########################################

A = np.array([[1,2],[3,4]])
B = np.array([[5,6],[7,8]])

print("\nMatrix A:\n", A)
print("Matrix B:\n", B)

# Matrix multiplication
print("A dot B:\n", np.dot(A,B))

# Transpose
print("A Transposed:\n", A.T)

# Determinant
print("Determinant of A:", np.linalg.det(A))

# Inverse
print("Inverse of A:\n", np.linalg.inv(A))

########################################
# 12. Saving and Loading Arrays
########################################

arr = np.array([1,2,3,4,5])
np.save("my_array.npy", arr)  # save in binary format
loaded_arr = np.load("my_array.npy")
print("\nLoaded array:", loaded_arr)

np.savetxt("my_array.txt", arr)  # save as text file
loaded_txt = np.loadtxt("my_array.txt")
print("Loaded text array:", loaded_txt)

########################################
# 13. Summary
########################################
print("\nNumPy concepts covered: Array creation, indexing, slicing, boolean indexing, reshaping, stacking, broadcasting, mathematical operations, linear algebra, saving/loading arrays.")
