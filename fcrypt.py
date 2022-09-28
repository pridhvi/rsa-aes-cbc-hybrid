import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import argparse

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument('-e', action='store_true')
group.add_argument('-d', action='store_true')

parser.add_argument(dest='arg1', type=str)
parser.add_argument(dest='arg2', type=str)
parser.add_argument(dest='arg3', type=str)
parser.add_argument(dest='arg4', type=str)

args = parser.parse_args()

def pad_message(message):
    number_of_bytes_to_pad = 16 - len(message) % 16
    ascii_string = chr(number_of_bytes_to_pad)
    padding_str = number_of_bytes_to_pad * ascii_string
    padded_message = message + padding_str
    return padded_message

def unpad_message(message):
    last_character = message[len(message) - 1:]
    bytes_to_remove = ord(last_character)
    return message[:-bytes_to_remove]

# AES-CBC Encryption
def aes_cbc_encrypt(message, cipher):
    message = pad_message(message).encode()
    encryptor = cipher.encryptor()
    enc_message = encryptor.update(message) + encryptor.finalize()
    return enc_message

# AES-CBC Decryption
def aes_cbc_decrypt(enc_message, cipher):
    decryptor = cipher.decryptor()
    message = decryptor.update(enc_message) + decryptor.finalize()
    return unpad_message(message)

def symmetrical_encrypt(message):
    session_key = os.urandom(32) # 32 bytes = 256 bits
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    return aes_cbc_encrypt(message, cipher), session_key, iv

def symmetrical_decrypt(message, session_key, iv):
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    return aes_cbc_decrypt(message, cipher)

def rsa_encrypt(session_key, receiver_public_key):
    return receiver_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(enc_session_key, receiver_private_key):
    return receiver_private_key.decrypt(
        enc_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def extract_args_encryption():
    args = parser.parse_args()

    # receiver_public_key
    with open(args.arg1, "rb") as file: 
        receiver_public_key = serialization.load_pem_public_key(file.read())

    # sender_private_key
    with open(args.arg2, "rb") as key_file: 
        sender_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # message
    with open(args.arg3, "r") as file: 
        message = file.read()

    output_file = args.arg4

    return receiver_public_key, sender_private_key, message, output_file

def extract_args_decryption():
    # receiver_private_key
    with open(args.arg1, "rb") as key_file: 
        receiver_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
        #print(key_file.read())
    
    # sender_public_key
    with open(args.arg2, "rb") as key_file: 
        sender_public_key = serialization.load_pem_public_key(key_file.read())
    
    # enc_package
    with open(args.arg3, "rb") as file:
        enc_package = file.read()

    output_file = args.arg4
    return receiver_private_key, sender_public_key, enc_package, output_file

def write_output(message, output_file):
    with open(output_file, "wb") as out_file:
        out_file.write(message)

def encrypt():
    receiver_public_key, sender_private_key, message, output_file = extract_args_encryption()
    enc_message, session_key, iv = symmetrical_encrypt(message)
    enc_session_key = rsa_encrypt(session_key, receiver_public_key)
    enc_package = enc_message + enc_session_key + iv
    write_output(enc_package, output_file)

def decrypt():
    receiver_private_key, sender_public_key, enc_package, output_file = extract_args_decryption()
    iv = enc_package[-16:]
    enc_session_key = enc_package[-272:-16]
    enc_message = enc_package[:-272]
    session_key = rsa_decrypt(enc_session_key, receiver_private_key)
    message = symmetrical_decrypt(enc_message, session_key, iv)
    write_output(message, output_file)

def main():
    if(args.e):
        encrypt()
    elif(args.d):
        decrypt()
    else:
        print("Error: Invalid command.")

main()