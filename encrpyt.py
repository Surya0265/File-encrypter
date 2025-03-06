from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os



def encrypt_file(input_file, output_file, key):
    # Generate a random IV (Nonce)
    nonce = get_random_bytes(12)  # 12 bytes for AES-GCM
    
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Read file and encrypt
    with open(input_file, 'rb') as f:
        plaintext = f.read()
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Save encrypted file (store nonce, tag, and ciphertext)
    with open(output_file, 'wb') as f:
        f.write(nonce + tag + ciphertext)

    print(f"File '{input_file}' encrypted successfully!")

# Generate a random AES-256 key (32 bytes)
key = get_random_bytes(32)  

# Encrypt file (Change 'sample.pdf' to your file)
encrypt_file("23N257_certificate.pdf", "encrypted.bin", key)

def decrypt_file(encrypted_file, output_file, key):
    with open(encrypted_file, 'rb') as f:
        nonce = f.read(12)  # Read 12-byte nonce
        tag = f.read(16)    # Read 16-byte authentication tag
        ciphertext = f.read()

    # Create AES cipher for decryption
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    try:
        # Decrypt file
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        print(f"File '{encrypted_file}' decrypted successfully!")

    except ValueError:
        print("Decryption failed! Invalid key or file modified.")

# Decrypt file
decrypt_file("encrypted.bin", "decrypted.pdf", key)