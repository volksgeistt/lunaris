"""
A secure custom encryption system using predefined character mappings
with special characters: ./_-+=!~
"""

import os
import hashlib
import secrets
import base64
from typing import Dict, Optional, Tuple


class Lunaris:
    """    
    Features:
    - Predefined character mapping dictionary
    - Salt-based key derivation
    - Input validation and sanitization
    - Secure error handling
    - Professional code structure
    """
    
    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize the cipher with optional master key for enhanced security.
        
        Args:
            master_key (str, optional): Master key for additional encryption layer
        """
        self._master_key = master_key
        self._salt = None
        self._initialize_cipher_maps()
    
    def _initialize_cipher_maps(self) -> None:
        """Initialize predefined encryption and decryption mappings."""
        self._encryption_map: Dict[str, str] = {
            'a': './', 'b': '._', 'c': '.-', 'd': '.+', 'e': '.=',
            'f': '.!', 'g': '.~', 'h': '/.', 'i': '/_', 'j': '/-',
            'k': '/+', 'l': '/=', 'm': '/!', 'n': '/~', 'o': '_.',
            'p': '_/', 'q': '_-', 'r': '_+', 's': '_=', 't': '_!',
            'u': '_~', 'v': '-.', 'w': '-/', 'x': '-_', 'y': '-+', 'z': '-=',
            
            'A': '-!', 'B': '-~', 'C': '+.', 'D': '+/', 'E': '+_',
            'F': '+-', 'G': '+=', 'H': '+!', 'I': '+~', 'J': '=.',
            'K': '=/', 'L': '=_', 'M': '=-', 'N': '=+', 'O': '=!',
            'P': '=~', 'Q': '!.', 'R': '!/', 'S': '!_', 'T': '!-',
            'U': '!+', 'V': '!=', 'W': '!~', 'X': '~.', 'Y': '~/', 'Z': '~_',
            
            '0': '~-', '1': '~+', '2': '~=', '3': '~!', '4': '~~',
            '5': '..', '6': '//', '7': '__', '8': '--', '9': '++',
            
            ' ': '==', '.': '!!', ',': '.,', '?': '.?', '!': '.!!',
            ':': '.:', ';': '.;', '"': '."', "'": ".'", '-': '.--',
            '+': '.++', '=': '.==', '_': '.___', '(': '.((', ')': '.))',
            '[': '.[', ']': '.]', '{': '.{', '}': '.}', '@': '.@',
            '#': '.#', '$': '.$', '%': '.%', '&': '.&', '*': '.*',
            '/': './/', '\\': '.\\', '|': '.|', '<': '.<', '>': '.>',
            '\n': '.\\n', '\t': '.\\t', '\r': '.\\r'
        }
        
        self._decryption_map: Dict[str, str] = {
            v: k for k, v in self._encryption_map.items()
        }
        
        self._validate_mappings()
    
    def _validate_mappings(self) -> None:
        """Validate encryption mappings for conflicts and completeness."""
        if len(self._encryption_map) != len(self._decryption_map):
            raise ValueError("Encryption mapping contains duplicate values")
        
        required_chars = set('abcdefghijklmnopqrstuvwxyz' + 
                           'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + 
                           '0123456789 .,!?')
        missing_chars = required_chars - set(self._encryption_map.keys())
        if missing_chars:
            raise ValueError(f"Missing mappings for characters: {missing_chars}")
    
    def _generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt."""
        return secrets.token_bytes(16)
    
    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from master key and salt using PBKDF2."""
        if not self._master_key:
            return salt
        
        return hashlib.pbkdf2_hmac(
            'sha256',
            self._master_key.encode('utf-8'),
            salt,
            100000 
        )
    
    def _apply_additional_encryption(self, data: str, key: bytes) -> str:
        """Apply additional layer of encryption using derived key."""
        if not self._master_key:
            return data
        
        encrypted_bytes = []
        for i, char in enumerate(data):
            key_byte = key[i % len(key)]
            encrypted_bytes.append(ord(char) ^ key_byte)
        
        return base64.b64encode(bytes(encrypted_bytes)).decode('utf-8')
    
    def _remove_additional_encryption(self, data: str, key: bytes) -> str:
        """Remove additional layer of encryption."""
        if not self._master_key:
            return data
        
        try:
            encrypted_bytes = base64.b64decode(data.encode('utf-8'))
            decrypted_chars = []
            for i, byte in enumerate(encrypted_bytes):
                key_byte = key[i % len(key)]
                decrypted_chars.append(chr(byte ^ key_byte))
            
            return ''.join(decrypted_chars)
        except Exception as e:
            raise ValueError(f"Failed to decrypt additional layer: {e}")
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using custom cipher.
        
        Args:
            plaintext (str): Text to encrypt
            
        Returns:
            str: Encrypted text with optional salt prefix
            
        Raises:
            ValueError: If input is invalid
        """
        if not isinstance(plaintext, str):
            raise ValueError("Input must be a string")
        
        if not plaintext:
            return ""
        
        self._salt = self._generate_salt()
        derived_key = self._derive_key(self._salt)
        
        encrypted_chars = []
        for char in plaintext:
            if char in self._encryption_map:
                encrypted_chars.append(self._encryption_map[char])
            else:
                encrypted_chars.append(f"[U{ord(char):04X}]")
        
        primary_encrypted = ''.join(encrypted_chars)
        
        final_encrypted = self._apply_additional_encryption(primary_encrypted, derived_key)
        
        if self._master_key:
            salt_b64 = base64.b64encode(self._salt).decode('utf-8')
            return f"{salt_b64}:{final_encrypted}"
        
        return final_encrypted
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext using custom cipher.
        
        Args:
            ciphertext (str): Text to decrypt
            
        Returns:
            str: Decrypted plaintext
            
        Raises:
            ValueError: If input is invalid or decryption fails
        """
        if not isinstance(ciphertext, str):
            raise ValueError("Input must be a string")
        
        if not ciphertext:
            return ""
        
        try:
            if self._master_key and ':' in ciphertext:
                salt_b64, encrypted_data = ciphertext.split(':', 1)
                salt = base64.b64decode(salt_b64.encode('utf-8'))
                derived_key = self._derive_key(salt)
                
                primary_encrypted = self._remove_additional_encryption(encrypted_data, derived_key)
            else:
                primary_encrypted = ciphertext
            
            decrypted_chars = []
            i = 0
            while i < len(primary_encrypted):
                if primary_encrypted[i:i+2] == '[U' and ']' in primary_encrypted[i:i+8]:
                    end_pos = primary_encrypted.find(']', i)
                    if end_pos != -1:
                        unicode_hex = primary_encrypted[i+2:end_pos]
                        try:
                            char_code = int(unicode_hex, 16)
                            decrypted_chars.append(chr(char_code))
                            i = end_pos + 1
                            continue
                        except ValueError:
                            pass
                
                found = False
                for length in range(5, 0, -1):  
                    if i + length <= len(primary_encrypted):
                        code = primary_encrypted[i:i+length]
                        if code in self._decryption_map:
                            decrypted_chars.append(self._decryption_map[code])
                            i += length
                            found = True
                            break
                
                if not found:
                    decrypted_chars.append('?') 
                    i += 1
            
            return ''.join(decrypted_chars)
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def get_cipher_info(self) -> Dict[str, any]:
        """
        Get information about the cipher configuration.
        
        Returns:
            dict: Cipher information
        """
        return {
            'cipher_type': 'Custom Character Substitution',
            'character_set': './_-+=!~',
            'total_mappings': len(self._encryption_map),
            'master_key_enabled': bool(self._master_key),
            'supports_unicode': True,
            'version': '1.0'
        }


class CipherManager:
    """High-level interface for cipher operations."""
    
    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize cipher manager.
        
        Args:
            master_key (str, optional): Master key for enhanced security
        """
        self._cipher = Lunaris(master_key)
    
    def encrypt_text(self, text: str) -> Tuple[bool, str]:
        """
        Encrypt text with error handling.
        
        Args:
            text (str): Text to encrypt
            
        Returns:
            tuple: (success: bool, result: str)
        """
        try:
            encrypted = self._cipher.encrypt(text)
            return True, encrypted
        except Exception as e:
            return False, f"Encryption error: {e}"
    
    def decrypt_text(self, ciphertext: str) -> Tuple[bool, str]:
        """
        Decrypt text with error handling.
        
        Args:
            ciphertext (str): Text to decrypt
            
        Returns:
            tuple: (success: bool, result: str)
        """
        try:
            decrypted = self._cipher.decrypt(ciphertext)
            return True, decrypted
        except Exception as e:
            return False, f"Decryption error: {e}"
    
    def get_info(self) -> Dict[str, any]:
        """Get cipher information."""
        return self._cipher.get_cipher_info()


def main():
    """Professional command-line interface."""
    print("=" * 60)
    print("PROFESSIONAL CUSTOM ENCRYPTION SYSTEM v1.0")
    print("=" * 60)
    
    use_master_key = input("Use master key for enhanced security? (y/n): ").lower() == 'y'
    master_key = None
    
    if use_master_key:
        master_key = input("Enter master key (or press Enter for none): ").strip()
        if not master_key:
            master_key = None
    
    cipher_manager = CipherManager(master_key)
    
    info = cipher_manager.get_info()
    print(f"\nCipher Configuration:")
    print(f"- Type: {info['cipher_type']}")
    print(f"- Character Set: {info['character_set']}")
    print(f"- Total Mappings: {info['total_mappings']}")
    print(f"- Enhanced Security: {info['master_key_enabled']}")
    print(f"- Unicode Support: {info['supports_unicode']}")
    
    while True:
        print("\n" + "-" * 40)
        print("OPERATIONS:")
        print("1. Encrypt Text")
        print("2. Decrypt Text") 
        print("3. Show Cipher Info")
        print("4. Exit")
        print("-" * 40)
        
        choice = input("Select operation (1-4): ").strip()
        
        if choice == '1':
            text = input("\nEnter text to encrypt: ")
            success, result = cipher_manager.encrypt_text(text)
            if success:
                print(f"\n✓ ENCRYPTED:")
                print(f"  {result}")
            else:
                print(f"\n✗ ERROR: {result}")
                
        elif choice == '2':
            ciphertext = input("\nEnter encrypted text to decrypt: ")
            success, result = cipher_manager.decrypt_text(ciphertext)
            if success:
                print(f"\n✓ DECRYPTED:")
                print(f"  {result}")
            else:
                print(f"\n✗ ERROR: {result}")
                
        elif choice == '3':
            info = cipher_manager.get_info()
            print(f"\nCIPHER INFORMATION:")
            for key, value in info.items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
                
        elif choice == '4':
            print("\nShutting down cipher system...")
            break
            
        else:
            print("\n✗ Invalid option. Please select 1-4.")


if __name__ == "__main__":
    main()
