import os
import json
from argon2 import PasswordHasher
from .encryption import EncryptionManager

class PasswordManager:
    def __init__(self):
        self.users_file = "users.json"
        self.passwords_file = "passwords.json"
    
    def is_master_password_set(self):
        return os.path.exists(self.users_file)

    def get_email(self):
        """Obtiene el email almacenado en el archivo de usuarios"""
        try:
            with open(self.users_file, 'r') as f:
                user_data = json.load(f)
                return user_data.get('email', '')
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return ''

    def set_master_password(self, password, email):
        ph = PasswordHasher()
        salt = EncryptionManager.generate_salt()
        
        # Crear estructura inicial vacía
        initial_data = {}
        
        # Cifrar datos iniciales
        em = EncryptionManager(password, salt)
        encrypted = em.encrypt(json.dumps(initial_data))
        
        # Guardar en users.json
        with open(self.users_file, 'w') as f:
            json.dump({
                "hash": ph.hash(password),
                "salt": salt.hex(),
                "email": email
            }, f)
        
        # Crear passwords.json con datos cifrados
        with open(self.passwords_file, 'w') as f:
            json.dump(encrypted, f)  # Datos ya cifrados
    
    def verify_master_password(self, password):
        try:
            with open(self.users_file) as f:
                data = json.load(f)
                ph = PasswordHasher()
                ph.verify(data["hash"], password)
                return True
        except:
            return False
    
    def get_passwords(self, master_password):
        try:
            # Si el archivo no existe, retornar estructura vacía
            if not os.path.exists(self.passwords_file):
                return {}

            with open(self.passwords_file, 'r') as f:
                encrypted_data = json.load(f)

            # Obtener salt del usuario
            with open(self.users_file, 'r') as f:
                user_data = json.load(f)
                salt = bytes.fromhex(user_data["salt"])

            # Descifrar datos
            em = EncryptionManager(master_password, salt)
            decrypted = em.decrypt(encrypted_data)
            return json.loads(decrypted)

        except (json.JSONDecodeError, KeyError, FileNotFoundError):
            # Si hay error, retornar diccionario vacío
            return {}
    
    def add_password(self, master_password, service, username, password):
        passwords = self.get_passwords(master_password)
        passwords[service] = {"username": username, "password": password}
        
        with open(self.users_file) as f:
            user_data = json.load(f)
            salt = bytes.fromhex(user_data["salt"])
        
        em = EncryptionManager(master_password, salt)
        encrypted = em.encrypt(json.dumps(passwords))
        
        with open(self.passwords_file, "w") as f:
            json.dump(encrypted, f)