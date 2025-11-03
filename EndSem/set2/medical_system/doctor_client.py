#!/usr/bin/env python3

"""
Doctor client implementation for the medical records management system.
Allows doctors to register, submit reports, and log expenses.
"""

import os
import json
import socket
import base64
from typing import Dict, Any, Optional
from Crypto.PublicKey import RSA
from crypto_utils import CryptoManager, SecureMessage

class DoctorClient:
    def __init__(self, host: str = '127.0.0.1', port: int = 65432):
        self.host = host
        self.port = port
        
        # Initialize crypto manager
        self.crypto = CryptoManager()
        self.crypto.generate_keys()
        
        # Server's public keys (received during connection)
        self.server_keys = None
        
        # Doctor's credentials
        self.doctor_id = None
        self.name = None
        self.department = None
    
    def connect(self) -> socket.socket:
        """Establish connection with server and identify as doctor"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        
        # Identify as doctor
        sock.sendall(b"DOCTOR")
        
        # Receive server's public keys
        self.server_keys = json.loads(sock.recv(4096).decode())
        
        return sock
    
    def register(self) -> bool:
        """Register as a new doctor"""
        print("\n=== Doctor Registration ===")
        self.name = input("Enter your name: ")
        self.department = input("Enter your department: ")
        
        with self.connect() as sock:
            # Send registration command
            sock.sendall(b"REGISTER")
            
            # Prepare registration data
            data = {
                'name': self.name,
                'encrypted_department': self.department,  # Would be encrypted in production
                'public_keys': self.crypto.get_public_keys()
            }
            
            # Generate AES key for this message
            aes_key = self.crypto.generate_aes_key()
            
            # Encrypt AES key with server's RSA public key
            server_rsa_key = RSA.import_key(self.server_keys['rsa'])
            encrypted_aes_key = self.crypto.encrypt_aes_key(aes_key, server_rsa_key)
            
            # Sign the data
            signature = self.crypto.sign_data(data)
            
            # Create secure message
            message = SecureMessage.create(data, aes_key, encrypted_aes_key, signature)
            
            # Send message
            sock.sendall(json.dumps(message).encode())
            
            # Get response
            response = json.loads(sock.recv(1024).decode())
            if response['status'] == 'success':
                self.doctor_id = response['doctor_id']
                print(f"\nRegistration successful! Your ID is: {self.doctor_id}")
                return True
            else:
                print("\nRegistration failed:", response.get('message', 'Unknown error'))
                return False
    
    def submit_report(self) -> bool:
        """Submit a medical report"""
        if not self.doctor_id:
            print("\nError: Please register first")
            return False
        
        print("\n=== Submit Medical Report ===")
        patient_name = input("Enter patient name: ")
        diagnosis = input("Enter diagnosis: ")
        treatment = input("Enter treatment plan: ")
        
        report_content = {
            'patient_name': patient_name,
            'diagnosis': diagnosis,
            'treatment': treatment
        }
        
        with self.connect() as sock:
            # Send report submission command
            sock.sendall(b"SUBMIT_REPORT")
            
            # Generate AES key for report encryption
            report_key = self.crypto.generate_aes_key()
            
            # Encrypt report content
            encrypted_content, tag = self.crypto.encrypt_data(report_content, report_key)
            
            # Prepare report data
            data = {
                'doctor_id': self.doctor_id,
                'encrypted_content': base64.b64encode(encrypted_content).decode(),
                'content_tag': base64.b64encode(tag).decode()
            }
            
            # Generate AES key for this message
            aes_key = self.crypto.generate_aes_key()
            
            # Encrypt AES key with server's RSA public key
            server_rsa_key = RSA.import_key(self.server_keys['rsa'])
            encrypted_aes_key = self.crypto.encrypt_aes_key(aes_key, server_rsa_key)
            
            # Sign the data
            signature = self.crypto.sign_data(data)
            
            # Create secure message
            message = SecureMessage.create(data, aes_key, encrypted_aes_key, signature)
            
            # Send message
            sock.sendall(json.dumps(message).encode())
            
            # Get response
            response = json.loads(sock.recv(1024).decode())
            if response['status'] == 'success':
                print("\nReport submitted successfully!")
                return True
            else:
                print("\nReport submission failed:", response.get('message', 'Unknown error'))
                return False
    
    def log_expense(self) -> bool:
        """Log a medical expense"""
        if not self.doctor_id:
            print("\nError: Please register first")
            return False
        
        print("\n=== Log Medical Expense ===")
        try:
            amount = float(input("Enter expense amount: "))
        except ValueError:
            print("\nError: Please enter a valid number")
            return False
        
        with self.connect() as sock:
            # Send expense logging command
            sock.sendall(b"LOG_EXPENSE")
            
            # Prepare expense data
            data = {
                'doctor_id': self.doctor_id,
                'encrypted_amount': str(amount)  # Would be encrypted in production
            }
            
            # Send data
            message = {'data': json.dumps(data)}
            sock.sendall(json.dumps(message).encode())
            
            # Get response
            response = json.loads(sock.recv(1024).decode())
            if response['status'] == 'success':
                print("\nExpense logged successfully!")
                return True
            else:
                print("\nExpense logging failed:", response.get('message', 'Unknown error'))
                return False
    
    def run(self) -> None:
        """Main client loop"""
        while True:
            print("\n=== Medical Records System - Doctor Client ===")
            print("1. Register")
            print("2. Submit Report")
            print("3. Log Expense")
            print("4. Exit")
            
            choice = input("\nEnter your choice (1-4): ")
            
            if choice == '1':
                self.register()
            elif choice == '2':
                self.submit_report()
            elif choice == '3':
                self.log_expense()
            elif choice == '4':
                if self._confirm_exit():
                    break
            else:
                print("\nInvalid choice. Please try again.")
    
    def _confirm_exit(self) -> bool:
        """Confirm before exiting"""
        confirm = input("\nAre you sure you want to exit? (y/n): ")
        return confirm.lower() == 'y'

if __name__ == "__main__":
    client = DoctorClient()
    client.run()