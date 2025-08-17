from customCrypt import Lunaris

cipher = Lunaris()

# Encrypt 
message = "Hello World!"
encrypted = cipher.encrypt(message)
print(f"Encrypted: {encrypted}")

# Decrypt 
decrypted = cipher.decrypt(encrypted)
print(f"Decrypted: {decrypted}")

# Verify
assert message == decrypted
print("Success!")
