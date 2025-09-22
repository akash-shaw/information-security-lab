# Python OOP Teaching Script
# Author: ChatGPT
# Purpose: Teach Object-Oriented Programming (OOP) in Python with detailed explanations

########################################
# 1. Introduction to OOP
########################################
# OOP allows us to structure code using objects.
# Objects have attributes (data) and methods (functions).
# Python supports OOP through classes.

########################################
# 2. Basic Class and Object
########################################

# Define a simple class
class Person:
    # The __init__ method is called a constructor
    # It is used to initialize object attributes
    def __init__(self, name, age):
        self.name = name  # attribute
        self.age = age    # attribute
    
    # Method: a function inside a class
    def introduce(self):
        print(f"Hello! My name is {self.name} and I am {self.age} years old.")

# Create an object (instance) of the class
akash = Person("Akash", 20)
akash.introduce()  # call method on object

# Multiple objects
rohit = Person("Rohit", 25)
rohit.introduce()

########################################
# 3. Instance, Class, and Static Variables
########################################

class Example:
    class_variable = "I am a class variable"  # shared by all objects
    
    def __init__(self, instance_var):
        self.instance_var = instance_var  # unique to each object
    
    @staticmethod
    def static_method():
        print("I am a static method. I do not access instance or class variables.")
    
    @classmethod
    def class_method(cls):
        print("I am a class method. I can access class variables:", cls.class_variable)

# Create objects
obj1 = Example("Instance 1")
obj2 = Example("Instance 2")

print(obj1.instance_var)  # Instance variable
print(obj2.instance_var)

print(Example.class_variable)  # Class variable shared by all
Example.static_method()
Example.class_method()

########################################
# 4. Encapsulation (Private Attributes)
########################################
# Encapsulation hides the internal data of an object

class BankAccount:
    def __init__(self, owner, balance):
        self.owner = owner
        self.__balance = balance  # private attribute (name mangling)
    
    # Getter method
    def get_balance(self):
        return self.__balance
    
    # Setter method
    def deposit(self, amount):
        if amount > 0:
            self.__balance += amount
        else:
            print("Deposit must be positive!")
    
    def withdraw(self, amount):
        if amount <= self.__balance:
            self.__balance -= amount
        else:
            print("Insufficient balance!")

account = BankAccount("Akash", 1000)
print(account.owner)
print(account.get_balance())  # access private balance safely

account.deposit(500)
print(account.get_balance())

account.withdraw(200)
print(account.get_balance())

########################################
# 5. Inheritance
########################################
# Inheritance allows a class (child) to inherit attributes and methods from another class (parent)

class Animal:
    def __init__(self, name):
        self.name = name
    
    def speak(self):
        print(f"{self.name} makes a sound.")

class Dog(Animal):  # Dog inherits from Animal
    def speak(self):  # Method overriding (polymorphism)
        print(f"{self.name} barks!")

class Cat(Animal):
    def speak(self):
        print(f"{self.name} meows!")

dog = Dog("Tommy")
cat = Cat("Kitty")

dog.speak()  # Tommy barks!
cat.speak()  # Kitty meows!

########################################
# 6. Polymorphism
########################################
# Polymorphism allows objects to be treated as instances of their parent class
# The same method can behave differently for different objects

animals = [Dog("Rex"), Cat("Luna"), Animal("GenericAnimal")]

for animal in animals:
    animal.speak()  # same method name, different behavior

########################################
# 7. Abstraction
########################################
# Abstraction hides the internal details and shows only functionality
# Achieved using abstract base classes

from abc import ABC, abstractmethod

class Vehicle(ABC):
    @abstractmethod
    def start_engine(self):
        pass  # abstract method, must be implemented by child class

class Car(Vehicle):
    def start_engine(self):
        print("Car engine started.")

class Bike(Vehicle):
    def start_engine(self):
        print("Bike engine started.")

car = Car()
bike = Bike()

car.start_engine()
bike.start_engine()

########################################
# 8. Operator Overloading
########################################
# You can redefine how operators work for your objects

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    def __add__(self, other):  # overload +
        return Point(self.x + other.x, self.y + other.y)
    
    def __str__(self):  # string representation
        return f"({self.x}, {self.y})"

p1 = Point(2, 3)
p2 = Point(4, 5)
p3 = p1 + p2  # uses __add__
print("Sum of points:", p3)

########################################
# 9. Composition (HAS-A Relationship)
########################################
# Composition is when one class contains another class

class Engine:
    def start(self):
        print("Engine started.")

class VehicleWithEngine:
    def __init__(self):
        self.engine = Engine()  # composition
    
    def start_vehicle(self):
        self.engine.start()
        print("Vehicle is ready to go!")

v = VehicleWithEngine()
v.start_vehicle()

########################################
# 10. Special Methods / Dunder Methods
########################################
# Python provides special methods like __init__, __str__, __len__, etc.

class Book:
    def __init__(self, title, author, pages):
        self.title = title
        self.author = author
        self.pages = pages
    
    def __str__(self):
        return f"'{self.title}' by {self.author}"
    
    def __len__(self):
        return self.pages

book = Book("Python Programming", "Akash", 300)
print(book)          # __str__ is called
print(len(book))     # __len__ is called

########################################
# 11. Summary
########################################
print("OOP concepts covered: Classes, Objects, Attributes, Methods, Encapsulation, Inheritance, Polymorphism, Abstraction, Operator Overloading, Composition, Special Methods")

