import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate encryption key from password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def create_fernet(key: bytes) -> Fernet:
    """Create a Fernet instance from a key"""
    return Fernet(key)

def save_key_and_salt(file_path: str, key: bytes, salt: bytes) -> None:
    """Save encryption key and salt to file for recovery"""
    with open(file_path, 'wb') as f:
        f.write(key + b'\n' + salt)

def load_key_and_salt(file_path: str) -> tuple[bytes, bytes]:
    """Load encryption key and salt from file"""
    with open(file_path, 'rb') as f:
        data = f.read().split(b'\n')
        if len(data) >= 2:
            return data[0], data[1]
    raise ValueError("Invalid key file format")
