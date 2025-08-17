# 🌙 Lunaris Encryption System

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![Security](https://img.shields.io/badge/security-PBKDF2+Salt-orange.svg)](https://en.wikipedia.org/wiki/PBKDF2)

A secure, custom encryption system featuring predefined character mappings with cryptographically strong key derivation and multi-layered protection.

## ✨ Features

- **🔐 Custom Character Substitution**: Proprietary mapping system using special characters (`./_-+=!~`)
- **🧂 Salt-Based Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
- **🔒 Dual-Layer Protection**: Optional master key for enhanced security
- **🌐 Unicode Support**: Handles any Unicode character through fallback encoding
- **⚡ Professional CLI**: Interactive command-line interface
- **🛡️ Secure Error Handling**: Comprehensive input validation and sanitization
- **📊 Mapping Validation**: Automatic conflict detection in cipher mappings

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/volksgeistt/lunaris
cd lunaris

# No additional dependencies required - uses Python standard library only!
```

### Basic Usage

```python
from customCrypt import Lunaris, CipherManager

# Simple encryption without master key
cipher = Lunaris()
encrypted = cipher.encrypt("Hello, World!")
decrypted = cipher.decrypt(encrypted)
print(decrypted)  # Output: Hello, World!

# Enhanced security with master key
secure_cipher = Lunaris(master_key="your-secret-key")
encrypted = secure_cipher.encrypt("Sensitive data")
decrypted = secure_cipher.decrypt(encrypted)
```

### Command Line Interface

```bash
python customCrypt.py
```

## 📖 Detailed Usage

### Basic Encryption

```python
from customCrypt import CipherManager

# Initialize cipher manager
manager = CipherManager()

# Encrypt text
success, encrypted = manager.encrypt_text("Secret message")
if success:
    print(f"Encrypted: {encrypted}")

# Decrypt text
success, decrypted = manager.decrypt_text(encrypted)
if success:
    print(f"Decrypted: {decrypted}")
```

### Advanced Security with Master Key

```python
# Initialize with master key for enhanced security
secure_manager = CipherManager(master_key="my-super-secret-key-2024")

# Encryption with dual-layer protection
success, encrypted = secure_manager.encrypt_text("Top secret information")
print(f"Secure encrypted: {encrypted}")

# Output format: [salt]:[encrypted_data]
# Example: "kJ8n2mP5qR7s9T1w3X6z8B4c=:VGhpcyBpcyBlbmNyeXB0ZWQ="
```

### Unicode and Special Characters

```python
cipher = Lunaris()

# Handles Unicode characters automatically
text = "Hello 🌙 Unicode: αβγ 中文 العربية"
encrypted = cipher.encrypt(text)
decrypted = cipher.decrypt(encrypted)
print(decrypted)  # Perfect reconstruction
```

## 🔧 API Reference

### `Lunaris` Class

The core encryption engine.

#### Constructor
```python
Lunaris(master_key: Optional[str] = None)
```
- `master_key`: Optional master key for enhanced security

#### Methods

##### `encrypt(plaintext: str) -> str`
Encrypts plaintext using the custom cipher.

**Parameters:**
- `plaintext` (str): Text to encrypt

**Returns:**
- `str`: Encrypted text (with optional salt prefix if master key is used)

**Raises:**
- `ValueError`: If input is invalid

##### `decrypt(ciphertext: str) -> str`
Decrypts ciphertext using the custom cipher.

**Parameters:**
- `ciphertext` (str): Text to decrypt

**Returns:**
- `str`: Decrypted plaintext

**Raises:**
- `ValueError`: If input is invalid or decryption fails

##### `get_cipher_info() -> Dict[str, any]`
Returns information about the cipher configuration.

### `CipherManager` Class

High-level interface with error handling.

#### Methods

##### `encrypt_text(text: str) -> Tuple[bool, str]`
Encrypts text with comprehensive error handling.

**Returns:**
- `Tuple[bool, str]`: (success_flag, result_or_error_message)

##### `decrypt_text(ciphertext: str) -> Tuple[bool, str]`
Decrypts text with comprehensive error handling.

**Returns:**
- `Tuple[bool, str]`: (success_flag, result_or_error_message)

## 🔒 Security Features

### Character Mapping System

Lunaris uses a proprietary 1-to-2 character mapping system:

```python
# Example mappings
'a' → './'    'Z' → '~_'    '5' → '..'
'H' → '+!'    ' ' → '=='    '!' → '.!!'
```

**Total Coverage:**
- 26 lowercase letters
- 26 uppercase letters  
- 10 digits (0-9)
- 20+ common punctuation and special characters
- Unicode fallback: `[U####]` format for any character

### Key Derivation

When a master key is provided:

1. **Salt Generation**: 16 cryptographically secure random bytes
2. **Key Derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations
3. **XOR Encryption**: Additional layer using derived key
4. **Base64 Encoding**: Safe transport encoding

### Security Properties

- **No Key Storage**: Keys are derived on-demand
- **Salt Uniqueness**: Each encryption uses a fresh salt
- **Computational Hardness**: 100,000 PBKDF2 iterations
- **Character Set Obfuscation**: Non-obvious symbol mappings

## 📊 Performance

| Operation | Time Complexity | Notes |
|-----------|----------------|--------|
| Character Mapping | O(n) | Linear with input length |
| Key Derivation | O(1) | Fixed 100,000 iterations |
| Unicode Fallback | O(1) | Per character |
| Overall Encryption | O(n) | Scales linearly |

**Benchmark Results** (approximate):
- Small text (100 chars): ~1ms
- Medium text (1KB): ~10ms  
- Large text (100KB): ~500ms
- Key derivation overhead: ~50ms

## 🛡️ Security Considerations

### Strengths
- ✅ No dependency on external libraries
- ✅ Cryptographically strong salt generation
- ✅ Industry-standard key derivation (PBKDF2)
- ✅ Comprehensive input validation
- ✅ Unicode character support

### Limitations
- ⚠️ **Not AES**: Custom algorithm, not cryptographically analyzed
- ⚠️ **Deterministic Mapping**: Same character → same cipher pattern
- ⚠️ **Frequency Analysis**: Vulnerable without master key
- ⚠️ **Educational Purpose**: Use established algorithms for production

### Recommendations
- 🔑 Always use a strong master key for sensitive data
- 🔄 Combine with other security layers for production use
- 📝 Consider this a learning tool and obfuscation method
- 🧪 Perfect for educational cryptography demonstrations

### ✅ Ideal For
- Educational cryptography projects
- Code obfuscation and anti-reverse engineering
- Casual data hiding and personal notes
- Demonstrating encryption concepts
- CTF competitions and puzzles


### Areas for Contribution
- Performance optimizations
- Additional security layers
- GUI interface development
- Extended character set support
- Comprehensive test suite


**⚠️ Disclaimer**: Lunaris is designed for educational purposes and light obfuscation. For production systems requiring strong security, use established cryptographic libraries like `cryptography` or `PyCryptodome`.

