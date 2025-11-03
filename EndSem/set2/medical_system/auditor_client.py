#!/usr/bin/env python3

"""
Auditor client implementation for the medical records management system.
Allows auditors to verify reports and perform privacy-preserving analysis.
"""

import json
import socket
from typing import List, Dict, Any

class AuditorClient:
    def __init__(self, host: str = '127.0.0.1', port: int = 65432):
        self.host = host
        self.port = port
    
    def connect(self) -> socket.socket:
        """Establish connection with server and identify as auditor"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        
        # Identify as auditor
        sock.sendall(b"AUDITOR")
        
        return sock
    
    def search_department(self) -> List[Dict[str, str]]:
        """Search for doctors by department keyword"""
        print("\n=== Search by Department ===")
        keyword = input("Enter department keyword: ")
        
        with self.connect() as sock:
            # Send search command
            sock.sendall(b"SEARCH_DEPARTMENT")
            
            # Send search keyword
            sock.sendall(keyword.encode())
            
            # Get results
            results = json.loads(sock.recv(4096).decode())
            
            if results:
                print("\nDoctors found:")
                for doc in results:
                    print(f"ID: {doc['doctor_id']}, Name: {doc['name']}")
            else:
                print("\nNo doctors found matching that keyword")
            
            return results
    
    def sum_expenses(self) -> None:
        """Calculate sum of expenses"""
        print("\n=== Sum Expenses ===")
        print("1. Sum all expenses")
        print("2. Sum expenses for specific doctor")
        
        choice = input("\nEnter your choice (1-2): ")
        
        with self.connect() as sock:
            # Send sum command
            sock.sendall(b"SUM_EXPENSES")
            
            if choice == '2':
                doctor_id = input("Enter doctor ID: ")
                request = {'doctor_id': doctor_id}
            else:
                request = {}
            
            # Send request
            sock.sendall(json.dumps(request).encode())
            
            # Get result
            total = int(sock.recv(1024).decode())
            
            if choice == '2':
                print(f"\nTotal expenses for Doctor {doctor_id}: ${total:,.2f}")
            else:
                print(f"\nTotal expenses across all doctors: ${total:,.2f}")
    
    def verify_report(self) -> None:
        """Verify authenticity of a medical report"""
        print("\n=== Verify Report ===")
        try:
            report_id = int(input("Enter report ID: "))
        except ValueError:
            print("\nError: Please enter a valid number")
            return
        
        with self.connect() as sock:
            # Send verification command
            sock.sendall(b"VERIFY_REPORT")
            
            # Send report ID
            sock.sendall(str(report_id).encode())
            
            # Get result
            result = json.loads(sock.recv(1024).decode())
            
            if result['status'] == 'success':
                print("\nVerification Result:")
                print(f"Signature Valid: {result['verified']}")
                print(f"Timestamp: {result['timestamp']}")
            else:
                print("\nVerification failed:", result.get('message', 'Unknown error'))
    
    def list_records(self) -> None:
        """List all medical records"""
        with self.connect() as sock:
            # Send list command
            sock.sendall(b"LIST_RECORDS")
            
            # Get records
            records = json.loads(sock.recv(4096).decode())
            
            if records:
                print("\n=== Medical Records ===")
                print("ID    | Doctor ID | Timestamp")
                print("-" * 40)
                for record in records:
                    print(f"{record['id']:<6}| {record['doctor_id']:<10}| {record['timestamp']}")
            else:
                print("\nNo records found")
    
    def run(self) -> None:
        """Main client loop"""
        while True:
            print("\n=== Medical Records System - Auditor Client ===")
            print("1. Search by Department")
            print("2. Sum Expenses")
            print("3. Verify Report")
            print("4. List Records")
            print("5. Exit")
            
            choice = input("\nEnter your choice (1-5): ")
            
            if choice == '1':
                self.search_department()
            elif choice == '2':
                self.sum_expenses()
            elif choice == '3':
                self.verify_report()
            elif choice == '4':
                self.list_records()
            elif choice == '5':
                if self._confirm_exit():
                    break
            else:
                print("\nInvalid choice. Please try again.")
    
    def _confirm_exit(self) -> bool:
        """Confirm before exiting"""
        confirm = input("\nAre you sure you want to exit? (y/n): ")
        return confirm.lower() == 'y'

if __name__ == "__main__":
    client = AuditorClient()
    client.run()