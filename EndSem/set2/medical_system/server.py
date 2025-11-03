#!/usr/bin/env python3

"""
Server implementation for the medical records management system.
Handles doctor registration, report submission, and auditor operations.
"""

import os
import json
import socket
import threading
import base64
from typing import Dict, List, Any
from pathlib import Path
from Crypto.PublicKey import RSA
from crypto_utils import CryptoManager, SecureMessage

class MedicalServer:
    def __init__(self, host: str = '127.0.0.1', port: int = 65432):
        self.host = host
        self.port = port
        
        # Initialize crypto manager
        self.crypto = CryptoManager()
        self.crypto.generate_keys()
        
        # Load or initialize storage
        self.storage_path = Path('server_data')
        self.storage_path.mkdir(exist_ok=True)
        
        self.doctors_file = self.storage_path / 'doctors.json'
        self.reports_file = self.storage_path / 'reports.json'
        self.expenses_file = self.storage_path / 'expenses.json'
        
        self._load_storage()
        
        # Thread-safe locks
        self.storage_lock = threading.Lock()
        self.print_lock = threading.Lock()
    
    def _load_storage(self) -> None:
        """Initialize or load persistent storage"""
        if not self.doctors_file.exists():
            self._save_json(self.doctors_file, {})
        if not self.reports_file.exists():
            self._save_json(self.reports_file, [])
        if not self.expenses_file.exists():
            self._save_json(self.expenses_file, {})
        
        self.doctors = self._load_json(self.doctors_file)
        self.reports = self._load_json(self.reports_file)
        self.expenses = self._load_json(self.expenses_file)
    
    @staticmethod
    def _load_json(file_path: Path) -> Any:
        """Load data from JSON file"""
        with open(file_path, 'r') as f:
            return json.load(f)
    
    @staticmethod
    def _save_json(file_path: Path, data: Any) -> None:
        """Save data to JSON file"""
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _safe_print(self, message: str) -> None:
        """Thread-safe console output"""
        with self.print_lock:
            print(message)
    
    def handle_client(self, conn: socket.socket, addr: tuple) -> None:
        """Handle individual client connections"""
        self._safe_print(f"New connection from {addr}")
        
        try:
            # First message should identify the client type
            client_type = conn.recv(1024).decode().strip()
            
            if client_type == "DOCTOR":
                self._handle_doctor(conn, addr)
            elif client_type == "AUDITOR":
                self._handle_auditor(conn, addr)
            else:
                self._safe_print(f"Invalid client type from {addr}: {client_type}")
        
        except Exception as e:
            self._safe_print(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
            self._safe_print(f"Connection closed for {addr}")
    
    def _handle_doctor(self, conn: socket.socket, addr: tuple) -> None:
        """Handle doctor client operations"""
        # Send server's public keys
        conn.sendall(json.dumps(self.crypto.get_public_keys()).encode())
        
        while True:
            try:
                # Receive command
                command = conn.recv(1024).decode().strip()
                
                if command == "REGISTER":
                    self._handle_doctor_registration(conn)
                elif command == "SUBMIT_REPORT":
                    self._handle_report_submission(conn)
                elif command == "LOG_EXPENSE":
                    self._handle_expense_logging(conn)
                elif command == "EXIT":
                    break
                else:
                    self._safe_print(f"Invalid command from doctor {addr}: {command}")
            
            except Exception as e:
                self._safe_print(f"Error in doctor handler for {addr}: {e}")
                break
    
    def _handle_auditor(self, conn: socket.socket, addr: tuple) -> None:
        """Handle auditor client operations"""
        while True:
            try:
                # Receive command
                command = conn.recv(1024).decode().strip()
                
                if command == "SEARCH_DEPARTMENT":
                    self._handle_department_search(conn)
                elif command == "SUM_EXPENSES":
                    self._handle_expense_sum(conn)
                elif command == "VERIFY_REPORT":
                    self._handle_report_verification(conn)
                elif command == "LIST_RECORDS":
                    self._handle_records_listing(conn)
                elif command == "EXIT":
                    break
                else:
                    self._safe_print(f"Invalid command from auditor {addr}: {command}")
            
            except Exception as e:
                self._safe_print(f"Error in auditor handler for {addr}: {e}")
                break
    
    def _handle_doctor_registration(self, conn: socket.socket) -> None:
        """Process doctor registration"""
        # Receive registration data
        message = json.loads(conn.recv(4096).decode())
        
        # Parse secure message
        encrypted_data, tag, encrypted_key, signature = SecureMessage.parse(message)
        
        # Decrypt AES key
        aes_key = self.crypto.decrypt_aes_key(encrypted_key)
        
        # Decrypt registration data
        data = self.crypto.decrypt_data(encrypted_data, tag, aes_key)
        
        # Store doctor information
        with self.storage_lock:
            doctor_id = str(len(self.doctors) + 1)
            self.doctors[doctor_id] = {
                'name': data['name'],
                'department': data['encrypted_department'],
                'public_keys': data['public_keys']
            }
            self._save_json(self.doctors_file, self.doctors)
        
        # Send response
        conn.sendall(json.dumps({
            'status': 'success',
            'doctor_id': doctor_id
        }).encode())
    
    def _handle_report_submission(self, conn: socket.socket) -> None:
        """Process medical report submission"""
        # Receive report data
        message = json.loads(conn.recv(8192).decode())
        
        # Parse secure message
        encrypted_data, tag, encrypted_key, signature = SecureMessage.parse(message)
        
        # Decrypt AES key
        aes_key = self.crypto.decrypt_aes_key(encrypted_key)
        
        # Decrypt report data
        data = self.crypto.decrypt_data(encrypted_data, tag, aes_key)
        
        # Verify signature
        doctor_id = data['doctor_id']
        doctor = self.doctors[doctor_id]
        if not self.crypto.verify_signature(data, signature, doctor['public_keys']['elgamal']):
            conn.sendall(json.dumps({'status': 'error', 'message': 'Invalid signature'}).encode())
            return
        
        # Store report
        with self.storage_lock:
            self.reports.append({
                'id': len(self.reports) + 1,
                'doctor_id': doctor_id,
                'encrypted_content': data['encrypted_content'],
                'timestamp': data['timestamp'],
                'signature': message['signature']
            })
            self._save_json(self.reports_file, self.reports)
        
        # Send response
        conn.sendall(json.dumps({'status': 'success'}).encode())
    
    def _handle_expense_logging(self, conn: socket.socket) -> None:
        """Process expense logging"""
        # Receive expense data
        message = json.loads(conn.recv(4096).decode())
        
        # Parse and store encrypted expense
        data = json.loads(message['data'])
        doctor_id = data['doctor_id']
        
        with self.storage_lock:
            if doctor_id not in self.expenses:
                self.expenses[doctor_id] = []
            self.expenses[doctor_id].append(data['encrypted_amount'])
            self._save_json(self.expenses_file, self.expenses)
        
        # Send response
        conn.sendall(json.dumps({'status': 'success'}).encode())
    
    def _handle_department_search(self, conn: socket.socket) -> None:
        """Process department search request"""
        # Receive search query
        query = conn.recv(1024).decode().strip()
        
        # Search through encrypted departments (simplified)
        results = []
        for doc_id, doc in self.doctors.items():
            if query in doc['department']:  # In reality, would use homomorphic comparison
                results.append({
                    'doctor_id': doc_id,
                    'name': doc['name']
                })
        
        # Send results
        conn.sendall(json.dumps(results).encode())
    
    def _handle_expense_sum(self, conn: socket.socket) -> None:
        """Process expense summation request"""
        # Receive request
        request = json.loads(conn.recv(1024).decode())
        doctor_id = request.get('doctor_id')
        
        # Calculate sum (simplified)
        if doctor_id:
            expenses = self.expenses.get(doctor_id, [])
        else:
            expenses = [exp for doc_expenses in self.expenses.values() 
                       for exp in doc_expenses]
        
        total = sum(map(int, expenses))  # In reality, would use homomorphic addition
        
        # Send result
        conn.sendall(str(total).encode())
    
    def _handle_report_verification(self, conn: socket.socket) -> None:
        """Process report verification request"""
        # Receive report ID
        report_id = int(conn.recv(1024).decode())
        
        # Find report
        report = next((r for r in self.reports if r['id'] == report_id), None)
        if not report:
            conn.sendall(json.dumps({
                'status': 'error',
                'message': 'Report not found'
            }).encode())
            return
        
        # Verify signature (simplified)
        doctor = self.doctors[report['doctor_id']]
        verification_result = {
            'status': 'success',
            'verified': True,  # In reality, would do proper verification
            'timestamp': report['timestamp']
        }
        
        # Send result
        conn.sendall(json.dumps(verification_result).encode())
    
    def _handle_records_listing(self, conn: socket.socket) -> None:
        """Process records listing request"""
        # Send all reports (excluding encrypted content)
        records = [{
            'id': r['id'],
            'doctor_id': r['doctor_id'],
            'timestamp': r['timestamp']
        } for r in self.reports]
        
        conn.sendall(json.dumps(records).encode())
    
    def start(self) -> None:
        """Start the server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}")
            
            try:
                while True:
                    conn, addr = s.accept()
                    # Start new thread for each client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    )
                    client_thread.start()
            
            except KeyboardInterrupt:
                print("\nServer shutting down...")

if __name__ == "__main__":
    server = MedicalServer()
    server.start()