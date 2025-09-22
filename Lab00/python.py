# Python Teaching Script
# Author: ChatGPT
# Purpose: Teach Python from basics to advanced topics with detailed explanations

########################################
# 1. Basics of Python
########################################

# 1.1 Printing to the screen
print("Hello, World!")  # print() displays output to the console

# 1.2 Variables and data types
# Variables are used to store data
x = 10          # integer
y = 3.14        # float (decimal number)
name = "Akash"  # string
is_student = True  # boolean (True or False)

# 1.3 Printing variables
print("x =", x)
print("y =", y)
print("Name:", name)
print("Is student?", is_student)

# 1.4 Comments
# This is a single-line comment
"""
This is a multi-line comment
Useful for documenting code
"""

# 1.5 Basic arithmetic
a = 10
b = 3
print("a + b =", a + b)  # addition
print("a - b =", a - b)  # subtraction
print("a * b =", a * b)  # multiplication
print("a / b =", a / b)  # division (float)
print("a // b =", a // b)  # floor division (integer)
print("a % b =", a % b)  # modulus (remainder)
print("a ** b =", a ** b)  # exponentiation

########################################
# 2. Data Structures
########################################

# 2.1 Lists
fruits = ["apple", "banana", "cherry"]  # list of strings
print(fruits)
print(fruits[0])  # access first element
fruits.append("orange")  # add element at end
print("After append:", fruits)
fruits.remove("banana")  # remove element
print("After remove:", fruits)
print("List length:", len(fruits))  # length of list

# 2.2 Tuples
# Tuples are immutable lists
coordinates = (10, 20)
print(coordinates)
# coordinates[0] = 15  # This would cause an error

# 2.3 Sets
# Sets store unique elements
colors = {"red", "green", "blue", "red"}
print(colors)  # red appears only once
colors.add("yellow")
print("After add:", colors)

# 2.4 Dictionaries
# Store data in key-value pairs
person = {"name": "Akash", "age": 20, "city": "Bangalore"}
print(person)
print(person["name"])  # access value by key
person["age"] = 21  # update value
print("After update:", person)
person["profession"] = "Student"  # add new key-value
print("After adding profession:", person)

########################################
# 3. Conditional Statements
########################################

age = 18

if age >= 18:
    print("You are an adult")
elif age > 12:
    print("You are a teenager")
else:
    print("You are a child")

########################################
# 4. Loops
########################################

# 4.1 For loop
for i in range(5):  # range(5) = 0,1,2,3,4
    print("i =", i)

# 4.2 Looping over a list
for fruit in fruits:
    print("Fruit:", fruit)

# 4.3 While loop
count = 0
while count < 5:
    print("Count:", count)
    count += 1  # increment

########################################
# 5. Functions
########################################

# Functions are reusable blocks of code
def greet(name):
    """Function to greet someone"""
    print("Hello,", name)

greet("Akash")

# Function with return value
def add_numbers(a, b):
    return a + b

result = add_numbers(5, 7)
print("Sum =", result)

########################################
# 6. Classes and Objects (OOP)
########################################

# Object-Oriented Programming allows structuring code as objects

class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age
    
    def introduce(self):
        print(f"My name is {self.name} and I am {self.age} years old")

# Creating object
akash = Person("Akash", 20)
akash.introduce()

########################################
# 7. File Handling
########################################

# Writing to a file
with open("example.txt", "w") as file:
    file.write("Hello, this is a test file.\n")
    file.write("Python is fun!")

# Reading from a file
with open("example.txt", "r") as file:
    content = file.read()
    print("File content:\n", content)

########################################
# 8. Exception Handling
########################################

try:
    num = int(input("Enter a number: "))
    print("You entered:", num)
except ValueError:
    print("That's not a valid number!")

########################################
# 9. Modules and Libraries
########################################

import math  # import math module
print("Square root of 16:", math.sqrt(16))
print("Value of pi:", math.pi)

# Random numbers
import random
print("Random number between 1 and 10:", random.randint(1, 10))

########################################
# 10. Advanced Topics
########################################

# 10.1 List Comprehension
squares = [x**2 for x in range(10)]
print("Squares:", squares)

# 10.2 Lambda Functions (anonymous functions)
add = lambda a, b: a + b
print("Lambda add:", add(5, 3))

# 10.3 Map, Filter, Reduce
nums = [1, 2, 3, 4, 5]
# Map example
squared = list(map(lambda x: x**2, nums))
print("Map squared:", squared)
# Filter example
even = list(filter(lambda x: x % 2 == 0, nums))
print("Even numbers:", even)
# Reduce example
from functools import reduce
sum_all = reduce(lambda a, b: a + b, nums)
print("Sum using reduce:", sum_all)

# 10.4 Decorators
def decorator(func):
    def wrapper():
        print("Before function call")
        func()
        print("After function call")
    return wrapper

@decorator
def say_hello():
    print("Hello!")

say_hello()

# 10.5 Generators
def my_generator(n):
    for i in range(n):
        yield i  # yield returns a value and pauses

gen = my_generator(5)
for value in gen:
    print("Generated:", value)

# 10.6 Context Managers (with statement)
with open("example.txt", "r") as file:
    content = file.read()
    print("Using context manager:\n", content)

########################################
# 11. Summary
########################################
print("Python basics and advanced concepts covered in this script!")

