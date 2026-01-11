import string
import random

class PasswordGenerator:
    def __init__(self, length: int):
        self.length = length
        self.special_chars = "!?/@#&" 
  
    def create(self):
        all_possible = string.ascii_letters + self.special_chars
        password_list = [random.choice(all_possible) for _ in range(self.length)]
        
        if not any(char in self.special_chars for char in password_list):
            password_list[0] = random.choice(self.special_chars)
            
        if not any(char in string.ascii_letters for char in password_list):
            password_list[1] = random.choice(string.ascii_letters)
            
        random.shuffle(password_list)
        
        return ''.join(password_list)

# Storage of passwords 
class Storage:
  
  def __init__(self, file_name: str):
    self.file_name = file_name
  
  def read_file(self, account: str):
    self.account = account
    with open(self.file_name, 'r') as file:
      for line in file:
        file_parts = line.strip().split(';')
        if file_parts[0].lower() == self.account.lower():
          return file_parts[1]
        
    return f'No Account in password manager'
  
  # Method to add new account and password to the file
  def append_file(self, account: str, password: str):
    with open(self.file_name, 'a') as file:
      file.write(f'\n{account}; {password}')
        
  
#Cryptography class


import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class FileEncryption:
  
  def __init__(self, pwd: str):
    self.pwd = pwd.encode()
    self.salt = 16 
    self.pwd_validate = f'Password is Correct'
  
  def _generate_key(self, salt: bytes):
    kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
              )
    return base64.urlsafe_b64encode(kdf.derive(self.pwd))
    
  
  def encrypt_file(self, file_name:str):
    
  
  
  def decrypt_file(self, key, file_name:str):
     

