# Encryption and Decryption Project

This Python script demonstrates encryption and decryption using:
- **AES (Advanced Encryption Standard)** for symmetric encryption.
- **RSA (Rivest–Shamir–Adleman)** for asymmetric encryption.

## Features
- AES in CBC mode with key derivation.
- RSA encryption with public/private keys.

## How to Use
1. Clone the repository:
   ```bash
   git clone https://github.com/Dan-BaN/Data-Encryption-and-Decryption-Module.git
   cd Data-Encryption-and-Decryption-Module

OR 

2. Run the script:
bash
Copy code
python encryption_decryption.py

Project Overview

Encryption and Decryption Code Overview
This document describes the Python implementation of an encryption and decryption program using both symmetric encryption (AES) and asymmetric encryption (RSA). The goal of the program is to encrypt plaintext data, display the ciphertext, and then decrypt it back into its original form to demonstrate the functionality.

1. Features of the Program
Supported Encryption Methods:
Symmetric Encryption (AES):

Uses a password to generate an AES key.
Encrypts data using the AES algorithm in CBC mode with PKCS7 padding.
Decrypts the ciphertext back into the original plaintext.
Asymmetric Encryption (RSA):

Uses RSA public and private key pairs.
Encrypts data using the public key.
Decrypts ciphertext using the private key.
Other Features:
Generates random salts and initialization vectors (IVs) for added security in AES encryption.
Handles exceptions and provides meaningful error messages in case of invalid inputs or processing errors.
2. Modules Used
The program uses the cryptography library for cryptographic operations. Key modules include:

cryptography.hazmat.primitives.ciphers:
Provides the Cipher, algorithms, and modes classes for AES encryption.
cryptography.hazmat.primitives.kdf.pbkdf2:
Used to derive AES keys securely using the PBKDF2 key derivation function.
cryptography.hazmat.primitives.asymmetric.rsa:
Handles RSA key generation, encryption, and decryption.
cryptography.hazmat.primitives:
Contains tools for hashing and padding.
3. Implementation Details
3.1. Symmetric Encryption (AES)
Key Steps:
Key and IV Generation:

A password provided by the user is combined with a randomly generated salt.
The PBKDF2 algorithm derives a 256-bit AES key from the password and salt.
A random 16-byte initialization vector (IV) is generated.
python
Copy code
def generate_aes_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    return key, iv, salt
Encryption:

The plaintext is padded using PKCS7 to make its length a multiple of the block size (128 bits).
AES encryption in CBC mode is performed using the derived key and IV.
python
Copy code
def encrypt_aes(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext
Decryption:

The ciphertext is decrypted and unpadded to restore the original plaintext.
python
Copy code
def decrypt_aes(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()
3.2. Asymmetric Encryption (RSA)
Key Steps:
RSA Key Generation:

A private key is generated with a key size of 2048 bits.
The public key is derived from the private key.
python
Copy code
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key
Encryption:

The plaintext is encrypted using the RSA public key and OAEP padding.
python
Copy code
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
Decryption:

The ciphertext is decrypted using the RSA private key and the same OAEP padding.
python
Copy code
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
4. Main Program Workflow
The main program provides the user with the option to choose between symmetric encryption (AES) and asymmetric encryption (RSA). Based on the choice, it performs the following steps:

User Options:
Symmetric Encryption (AES):

Input plaintext and a password.
Generate an AES key and IV.
Encrypt the plaintext.
Decrypt the ciphertext and display the original plaintext.
Asymmetric Encryption (RSA):

Input plaintext.
Generate RSA key pairs.
Encrypt the plaintext using the public key.
Decrypt the ciphertext using the private key.
Code for the Main Program:
python
Copy code
def main():
    print("Encryption and Decryption Program")
    print("Choose the encryption method:")
    print("1. Symmetric Encryption (AES)")
    print("2. Asymmetric Encryption (RSA)")
    
    choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == "1":
        print("\nYou selected Symmetric Encryption (AES).")
        plaintext = input("Enter the plaintext to encrypt: ").strip()
        password = input("Enter a password for key generation: ").strip()
        
        key, iv, salt = generate_aes_key(password)
        ciphertext = encrypt_aes(plaintext, key, iv)
        print(f"\nEncrypted Ciphertext (AES): {ciphertext.hex()}")
        decrypted_text = decrypt_aes(ciphertext, key, iv)
        print(f"Decrypted Plaintext: {decrypted_text}")
    
    elif choice == "2":
        print("\nYou selected Asymmetric Encryption (RSA).")
        plaintext = input("Enter the plaintext to encrypt: ").strip()
        
        private_key, public_key = generate_rsa_keys()
        ciphertext = encrypt_rsa(plaintext, public_key)
        print(f"\nEncrypted Ciphertext (RSA): {ciphertext.hex()}")
        decrypted_text = decrypt_rsa(ciphertext, private_key)
        print(f"Decrypted Plaintext: {decrypted_text}")
    
    else:
        print("Invalid choice. Please restart the program and choose 1 or 2.")
5. Security Features
Random Salt and IV:

Every AES encryption operation uses a unique salt and IV, ensuring that even if the same plaintext is encrypted multiple times, the ciphertext will differ.
Key Derivation:

The password is securely converted into a key using the PBKDF2 algorithm with SHA256 hashing.
Secure Padding:

PKCS7 padding ensures that plaintexts of arbitrary lengths are compatible with block-based encryption.
RSA Security:

RSA encryption uses a 2048-bit key size, which is secure against modern attacks.
6. Error Handling
Missing Input: Prompts the user to enter both plaintext and password for AES encryption.
Invalid Operations: Handles exceptions such as decryption failures or input mismatches.
7. Usage Instructions
Run the program.
Select 1 for AES encryption or 2 for RSA encryption.
Follow the prompts to input plaintext and (for AES) a password.
View the encrypted and decrypted results.


