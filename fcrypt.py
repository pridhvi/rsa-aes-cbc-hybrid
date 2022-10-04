import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes, padding as pad
from cryptography.hazmat.primitives.asymmetric import padding
import argparse
import sys

# Argument parser
parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument('-e', action='store_true')
group.add_argument('-d', action='store_true')

parser.add_argument(dest='arg1', type=str)
parser.add_argument(dest='arg2', type=str)
parser.add_argument(dest='arg3', type=str)
parser.add_argument(dest='arg4', type=str)

args = parser.parse_args()

# Sign message using sender's private key
def sign_message(message, private_key):
    try:
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        sys.exit("Error: Signing the message failed.")

# Verify the signature using the sender's public key
def verify_message(message, public_key, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        sys.exit("Error: Invalid Signature!\nAborting decryption...")

# Pad the message for the size to be in multiples of 128bits
def pad_message(message):
    padder = pad.PKCS7(128).padder()
    return padder.update(message) + padder.finalize()

# Removing the pad when decrypting
def unpad_message(message):
    unpadder = pad.PKCS7(128).unpadder()
    return unpadder.update(message) + unpadder.finalize()

# AES-CBC Encryption
def aes_cbc_encrypt(message, cipher):
    message = pad_message(message)
    encryptor = cipher.encryptor()
    enc_message = encryptor.update(message) + encryptor.finalize()
    return enc_message

# AES-CBC Decryption
def aes_cbc_decrypt(enc_message, cipher):
    decryptor = cipher.decryptor()
    message = decryptor.update(enc_message) + decryptor.finalize()
    return unpad_message(message)

# Encrypt the message symmetrically
def symmetrical_encrypt(message):
    # Create random session key and initialisation vector
    session_key = os.urandom(32) # 32 bytes = 256 bits
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    return aes_cbc_encrypt(message, cipher), session_key, iv

# Decrypt the message symmetrically
def symmetrical_decrypt(message, session_key, iv):
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    return aes_cbc_decrypt(message, cipher)

# RSA encrypt the session key asymmetrically using receiver's public key
def rsa_encrypt(session_key, receiver_public_key):
    try:
        return receiver_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        sys.exit("Error: RSA encryption of the session key failed.")

# RSA decrypt the session key asymmetrically using receiver's private key
def rsa_decrypt(enc_session_key, receiver_private_key):
    return receiver_private_key.decrypt(
        enc_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Read the files passed as arguments for encryption
def extract_args_encryption():
    args = parser.parse_args()

    # receiver_public_key
    try:
        with open(args.arg1, "rb") as file: 
            if "pem" in args.arg1:
                receiver_public_key = serialization.load_pem_public_key(file.read())
            elif "der" in args.arg1:
                receiver_public_key = serialization.load_der_public_key(file.read())
    except:
        sys.exit("Error: Reading Receiver Public Key failed.")

    # sender_private_key
    try:
        with open(args.arg2, "rb") as key_file: 
            if "pem" in args.arg2:
                sender_private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            elif "der" in args.arg2:
                sender_private_key = serialization.load_der_private_key(
                    key_file.read(),
                    password=None
                )
    except:
        sys.exit("Error: Reading Sender Private Key failed.")

    # message
    try:
        with open(args.arg3, "rb") as file: 
            message = file.read()
    except:
        sys.exit("Error: Reading Plaintext Message failed.")

    output_file = args.arg4

    return receiver_public_key, sender_private_key, message, output_file

# Read the files passed as arguments for decryption
def extract_args_decryption():
    # receiver_private_key
    try:
        with open(args.arg1, "rb") as key_file:
            if "pem" in args.arg1:
                receiver_private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
            elif "der" in args.arg1:
                receiver_private_key = serialization.load_der_private_key(
                    key_file.read(),
                    password=None,
                )
    except:
        sys.exit("Error: Reading Receiver Private Key failed.")

    # sender_public_key
    try:
        with open(args.arg2, "rb") as key_file: 
            if "pem" in args.arg2:
                sender_public_key = serialization.load_pem_public_key(key_file.read())
            elif "der" in args.arg2:
                sender_public_key = serialization.load_der_public_key(key_file.read())
    except:
        sys.exit("Error: Reading Sender Public Key failed.")

    # enc_package
    try:
        with open(args.arg3, "rb") as file:
            enc_package = file.read()
    except:
        sys.exit("Error: Reading Encrypted Package failed.")

    output_file = args.arg4
    return receiver_private_key, sender_public_key, enc_package, output_file

# Write output to a file in bytes
def write_output(message, output_file):
    try:
        with open(output_file, "wb") as out_file:
            out_file.write(message)
    except:
        sys.exit("Error: Writing Output failed.")

# Handle all the encryption
def encrypt():
    # Extract keys and message from the input arguments
    print("Reading the message and keys...\n")
    receiver_public_key, sender_private_key, message, output_file = extract_args_encryption()

    # Symmetrically encrypt message
    print("Encrypting the message symmetrically using AES256-CBC...")
    enc_message, session_key, iv = symmetrical_encrypt(message)
    print("The message was encrypted!\n")

    # Sign the encrypted message
    print("Signing the encrypted message...")
    signature = sign_message(enc_message, sender_private_key)
    print("The encrypted message was signed!\n")

    # Asymmetrically encrypt the session key
    print("Encrypting the session key asymmetrically using RSA...")
    enc_session_key = rsa_encrypt(session_key, receiver_public_key)
    print("The session key was encrypted!\n")

    # enc_message = enc_message[-5:] + os.urandom(5) # Check signature by changing message
    # Pack the encrypted message, encrypted session key, iv, and signature in a single package
    enc_package = enc_message + enc_session_key + iv + signature

    # Write this package into the output file
    write_output(enc_package, output_file)
    print("The message was encrypted and written to the file \"" + output_file + "\"!")

# Handle all the decryption
def decrypt():
    # Extract keys and encrypted package from the input arguments
    print("Reading the message and keys...\n")
    receiver_private_key, sender_public_key, enc_package, output_file = extract_args_decryption()

    # Separate individual values from the encrypted package starting from the end
    signature = enc_package[-256:] # signature is the last 256 bytes
    iv = enc_package[-272:-256] # iv is 16 bytes before
    enc_session_key = enc_package[-528:-272] # encrypted session key is 256 bytes before
    enc_message = enc_package[:-528] # encrypted message is the rest of the bytes before

    # Verify the signature before decryption
    print("Verifying the signature of the encrypted message...")
    verify_message(enc_message, sender_public_key, signature)
    print("The signature was verified!\n")

    # Asymmetrically decrypt the session key
    print("Decrypting the session key asymmetrically...")
    session_key = rsa_decrypt(enc_session_key, receiver_private_key)
    print("The session key was decrypted!\n")

    # Symmetrically decrypt the encrypted message
    print("Decrypting the message symmetrically...\n")
    message = symmetrical_decrypt(enc_message, session_key, iv)
    
    # Write the decrypted message into the output file
    write_output(message, output_file)
    print("The message was decrypted and stored in the file \"" + output_file + "\"")

def main():
    # If -e flag do encryption
    if(args.e):
        print("Starting Encryption...\n")
        encrypt()
    # If -d flag do decryption
    elif(args.d):
        print("Starting Decryption...")
        decrypt()
    else:
        print("Error: Invalid command.")

main()