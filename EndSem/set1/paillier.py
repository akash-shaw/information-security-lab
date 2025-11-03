#!/usr/bin/env python3

import random
from math import gcd

def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False
    
    # Write n as 2^r * d + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = (x * x) % n
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        if n % 2 == 0:
            n += 1
        if is_prime(n):
            return n

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

class PaillierKey:
    def __init__(self, bits=1024):
        # Generate two large prime numbers
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        
        # Compute n = p * q
        self.n = p * q
        self.n_sq = self.n * self.n
        
        # Compute λ = lcm(p-1, q-1)
        self.lambda_ = lcm(p-1, q-1)
        
        # Compute g = n + 1
        self.g = self.n + 1
        
        # Compute μ = λ^-1 mod n
        self.mu = pow(self.lambda_, -1, self.n)

    def encrypt(self, m):
        if not 0 <= m < self.n:
            raise ValueError("Message must be in range [0, n)")
        
        # Choose random r in Z*_n
        r = random.randrange(1, self.n)
        while gcd(r, self.n) != 1:
            r = random.randrange(1, self.n)
        
        # Compute ciphertext
        c = (pow(self.g, m, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return PaillierCiphertext(c, self.n_sq)
    
    def decrypt(self, c):
        if not isinstance(c, PaillierCiphertext) and isinstance(c, int):
            c = PaillierCiphertext(c, self.n_sq)
        
        # Decrypt using CRT
        x = pow(c.value, self.lambda_, self.n_sq)
        L = (x - 1) // self.n
        m = (L * self.mu) % self.n
        return m

class PaillierCiphertext:
    def __init__(self, value, n_sq):
        self.value = value
        self.n_sq = n_sq
    
    def __add__(self, other):
        if isinstance(other, PaillierCiphertext):
            return PaillierCiphertext((self.value * other.value) % self.n_sq, self.n_sq)
        return NotImplemented
    
    def __mul__(self, scalar):
        if isinstance(scalar, int):
            return PaillierCiphertext(pow(self.value, scalar, self.n_sq), self.n_sq)
        return NotImplemented
    
    def ciphertext(self):
        return self.value