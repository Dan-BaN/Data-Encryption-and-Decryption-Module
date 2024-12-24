from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
import os

# Symmetric Encryption Functions
def generate_aes_key(password):
    salt = os.urandom(16)  # Random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())  # Derive key from password
    iv = os.urandom(16)  # Random IV
    return key, iv, salt

def encrypt_aes(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt_aes(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Asymmetric Encryption Functions
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode()

# Main Program
def main():
    print("Encryption and Decryption Program")
    print("Choose the encryption method:")
    print("1. Symmetric Encryption (AES)")
    print("2. Asymmetric Encryption (RSA)")
    
    choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == "1":
        # Symmetric Encryption
        print("\nYou selected Symmetric Encryption (AES).")
        plaintext = input("Enter the plaintext to encrypt: ").strip()
        password = input("Enter a password for key generation: ").strip()
        
        # Generate AES key and IV
        key, iv, salt = generate_aes_key(password)
        
        # Encrypt
        ciphertext = encrypt_aes(plaintext, key, iv)
        print(f"\nEncrypted Ciphertext (AES): {ciphertext}")
        
        # Decrypt
        decrypted_text = decrypt_aes(ciphertext, key, iv)
        print(f"Decrypted Plaintext: {decrypted_text}")
    
    elif choice == "2":
        # Asymmetric Encryption
        print("\nYou selected Asymmetric Encryption (RSA).")
        plaintext = input("Enter the plaintext to encrypt: ").strip()
        
        # Generate RSA keys
        private_key, public_key = generate_rsa_keys()
        
        # Encrypt
        ciphertext = encrypt_rsa(plaintext, public_key)
        print(f"\nEncrypted Ciphertext (RSA): {ciphertext}")
        
        # Decrypt
        decrypted_text = decrypt_rsa(ciphertext, private_key)
        print(f"Decrypted Plaintext: {decrypted_text}")
    
    else:
        print("Invalid choice. Please restart the program and choose 1 or 2.")

if __name__ == "__main__":
    main()
