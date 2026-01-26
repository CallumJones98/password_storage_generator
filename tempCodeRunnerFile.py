import os
import string
import random
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from zxcvbn import zxcvbn

#Generate Password
class PasswordGenerator:
    def __init__(self, lower_limit: int, upper_limit: int):
        self.lower_limit = lower_limit
        self.upper_limit = upper_limit
        self.special_chars = "!?/@#&"
  
    def create(self):
        while True:
            current_length = random.randint(self.lower_limit, self.upper_limit)
            
            num_specials = max(2, current_length // 3) 
            num_letters = current_length - num_specials
            
            password_list = (
                [random.choice(self.special_chars) for _ in range(num_specials)] +
                [random.choice(string.ascii_letters) for _ in range(num_letters)]
            )
            
            random.shuffle(password_list)
            candidate_pwd = ''.join(password_list)
            
            results = zxcvbn(candidate_pwd)
            if results['score'] >= 3:
                return candidate_pwd

#Data Management 
class Storage:
    def __init__(self, raw_data: str):
        self.lines = [line.strip() for line in raw_data.strip().split('\n') if line.strip()]
  
    def get_password(self, account: str):
        for line in self.lines:
            parts = line.split(';')
            if parts[0].strip().lower() == account.strip().lower():
                return parts[1].strip()
        return "No Account found."
  
    def add_entry(self, account: str, password: str):
        new_account = account.strip()
        for i, line in enumerate(self.lines):
            existing_acc = line.split(';')[0].strip()
            if existing_acc.lower() == new_account.lower():
                self.lines[i] = f"{existing_acc}; {password}"
                return f"Updated existing account: {existing_acc}"
        
        self.lines.append(f"{new_account}; {password}")
        return f"✨ Added new account: {new_account}"

    def delete_entry(self, account: str):
        target = account.strip().lower()
        original_count = len(self.lines)
        self.lines = [line for line in self.lines if line.split(';')[0].strip().lower() != target]
        return len(self.lines) < original_count

    def list_accounts(self):
        return [line.split(';')[0].strip() for line in self.lines if "MASTER;INITIALIZED" not in line]
        
    def get_full_data(self):
        return "\n".join(self.lines)

# Encryption Class
class FileEncryption:
    def __init__(self, pwd: str):
        self.pwd = pwd.encode()
        self.salt_size = 16 

    def _generate_key(self, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.pwd))
    
    def encrypt_vault(self, data: str, file_name: str):
        salt = os.urandom(self.salt_size)
        key = self._generate_key(salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        with open(file_name, 'wb') as file:
            file.write(salt + encrypted_data)
  
    def decrypt_vault(self, file_name: str) -> str:
        with open(file_name, 'rb') as file:
            file_content = file.read()
        salt = file_content[:self.salt_size]
        encrypted_data = file_content[self.salt_size:]
        key = self._generate_key(salt)
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode()

# Strength testing class 
def get_password_safety(password: str):
    results = zxcvbn(password)
    rankings = {0: 'Very Weak', 1: 'Weak', 2: 'Fair', 3: 'Strong', 4: 'Excellent'}
    return {
        "rank": rankings[results['score']],
        "crack_time": results['crack_times_display']['offline_fast_hashing_1e10_per_second']
    }

#Main Logic 
class PasswordManager:
    def __init__(self, file_name: str, master_password: str):
        self.file_name = file_name
        self.crypt = FileEncryption(master_password)
        if not os.path.exists(self.file_name):
            self.crypt.encrypt_vault("MASTER;INITIALIZED", self.file_name)

    def run_action(self, action_type: str, account: str = None, min_len: int = 12, max_len: int = 20):
            try:
                raw_data = self.crypt.decrypt_vault(self.file_name)
                store = Storage(raw_data)
                
                if action_type == "get":
                    return store.get_password(account)
                
                elif action_type == "list":
                    return store.list_accounts()
                    
                elif action_type == "add":
                    if max_len < 10:
                        return "Error: Maximum length is too short to guarantee a Strong password. Use at least 10."
                    if min_len > max_len:
                        return "Error: Lower limit cannot be higher than upper limit."

                    gen = PasswordGenerator(min_len, max_len)
                    new_pwd = gen.create()
                    
                    safety = get_password_safety(new_pwd)
                    
                    msg = store.add_entry(account, new_pwd)
                    self.crypt.encrypt_vault(store.get_full_data(), self.file_name)
                    
                    return {
                        "status": msg, 
                        "password": new_pwd, 
                        "strength": safety['rank'], 
                        "time": safety['crack_time'] 
                    }
                    
                elif action_type == "delete":
                    if store.delete_entry(account):
                        self.crypt.encrypt_vault(store.get_full_data(), self.file_name)
                        return f"Successfully deleted {account}."
                    return f"Account '{account}' not found."
                        
            except InvalidToken:
                return "AUTH_ERROR" 
              
          
# User Interaction
if __name__ == "__main__":
    print("--- SECURE VAULT v1.0 ---")
    m_pass = input("Master Password: ")
    vault_file = "vault.dat"
    pm = PasswordManager(vault_file, m_pass)

    while True:
        accounts = pm.run_action("list")
        if accounts == "AUTH_ERROR":
            print("Access Denied: Incorrect Master Password.")
            break

        print("\n[1] Add Password  [2] Get Password  [3] List Accounts  [4] Delete Account  [5] Exit")
        cmd = input("Select > ")

        if cmd == "1":
            acc = input("Account name: ")
            try:
                low = int(input("Minimum length: "))
                high = int(input("Maximum length: "))
                
                res = pm.run_action("add", account=acc, min_len=low, max_len=high)
                
                if isinstance(res, dict):
                    print(f"\nStatus: {res['status']}")
                    print(f"Generated Password: {res['password']}")
                    print(f"Strength Rank: {res['strength']}")
                    print(f"Estimated Crack Time: {res['time']}")
                else:
                    print(f"\n{res}")
            except ValueError:
                print("\nError: Please enter numbers for the length limits.")

        elif cmd == "2":
            acc = input("Account name: ")
            password = pm.run_action("get", account=acc)
            print(f"\nPassword for {acc}: {password}")

        elif cmd == "3":
            print("\nStored Accounts:")
            if accounts:
                for a in accounts:
                    print(f"- {a}")
            else:
                print("The vault is currently empty.")

        elif cmd == "4":
            acc = input("Account name to delete: ")
            confirm = input(f"Are you sure you want to delete {acc}? (y/n): ")
            if confirm.lower() == 'y':
                result = pm.run_action("delete", account=acc)
                print(f"\n{result}")

        elif cmd == "5":
            print("Vault locked. Goodbye.")
            break
        
        else:
            print("Invalid selection. Please try again.")