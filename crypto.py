import os
import base64
import logging
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag, InvalidKey

logger = logging.getLogger(__name__)

class CryptoManager:
    """Handles encryption and decryption of files."""
    
    KEY_LENGTH = 32  # 256 bits
    SALT_LENGTH = 16  # 128 bits
    IV_LENGTH = 12    # 96 bits for GCM mode
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate a random salt for key derivation."""
        return os.urandom(CryptoManager.SALT_LENGTH)
    
    @staticmethod
    def generate_iv() -> bytes:
        """Generate a random initialization vector."""
        return os.urandom(CryptoManager.IV_LENGTH)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive an encryption key from a password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=CryptoManager.KEY_LENGTH,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def encrypt_file(input_file_path: str, password: str) -> Tuple[str, Dict[str, Any]]:
        """
        Encrypt a file using AES-GCM.
        
        Args:
            input_file_path: Path to the file to encrypt
            password: Password to derive the encryption key from
            
        Returns:
            Tuple containing:
                - Path to the encrypted file
                - Dictionary with encryption metadata (salt, iv, tag)
        """
        try:
            # Generate salt and derive key
            salt = CryptoManager.generate_salt()
            key = CryptoManager.derive_key(password, salt)
            
            # Generate IV
            iv = CryptoManager.generate_iv()
            
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Read the input file
            with open(input_file_path, 'rb') as f:
                plaintext = f.read()
            
            # Encrypt the data
            ciphertext = aesgcm.encrypt(iv, plaintext, None)
            
            # The tag is appended to the ciphertext by AESGCM
            # We'll save the ciphertext as a new file
            encrypted_filename = f"{os.path.basename(input_file_path)}.enc"
            output_file_path = os.path.join(os.path.dirname(input_file_path), encrypted_filename)
            
            with open(output_file_path, 'wb') as f:
                f.write(ciphertext)
            
            # Return encryption metadata
            return output_file_path, {
                'salt': base64.b64encode(salt).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'algorithm': 'AES-256-GCM'
            }
        
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise
    
    @staticmethod
    def decrypt_file(encrypted_file_path: str, output_file_path: str, password: str, 
                    salt_b64: str, iv_b64: str) -> bool:
        """
        Decrypt a file that was encrypted with AES-GCM.
        
        Args:
            encrypted_file_path: Path to the encrypted file
            output_file_path: Path where decrypted file should be saved
            password: Password used for encryption
            salt_b64: Base64-encoded salt used for key derivation
            iv_b64: Base64-encoded initialization vector
            
        Returns:
            Boolean indicating success
        """
        try:
            # Decode metadata
            salt = base64.b64decode(salt_b64)
            iv = base64.b64decode(iv_b64)
            
            # Derive the key
            key = CryptoManager.derive_key(password, salt)
            
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Read the encrypted file
            with open(encrypted_file_path, 'rb') as f:
                ciphertext = f.read()
            
            # Decrypt the data
            try:
                plaintext = aesgcm.decrypt(iv, ciphertext, None)
            except InvalidTag:
                logger.error("Decryption failed: Invalid authentication tag")
                return False
            
            # Write the decrypted data
            with open(output_file_path, 'wb') as f:
                f.write(plaintext)
            
            return True
        
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return False
