import os
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.fernet import Fernet

class EncryptionManager:
    def __init__(self, master_password, salt):
        self.key = self.derive_key(master_password, salt)
        self.cipher = Fernet(self.key)
    
    @staticmethod
    def derive_key(password, salt):
        key = hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
        return base64.urlsafe_b64encode(key)
    
    def encrypt(self, data):
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    @staticmethod
    def generate_salt():
        return os.urandom(16)