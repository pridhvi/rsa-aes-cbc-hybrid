# RSA-AES256-CBC-Hybrid

An implementation of a hybrid encryption system involving RSA, AES256-CBC

## Requirements

1. Receiver public and private keys (RSA keys in pem format)
2. Sender public and private keys (RSA keys in pem format) - (This is for signing which will be implemented)
3. Input file which is to be encrypted

## Encrypt command

`python3 fcrypt.py -e <receiver_public_key_file> <sender_private_key_file> <input_plaintext_file> <output_ciphertext_file>`

## Decrypt command

`python3 fcrypt.py -d <receiver_private_key_file> <sender_public_key_file> <input_ciphertext_file> <output_plaintext_file>`


## Encryption Process

The input plaintext file is read.

### AES256-CBC

A random 256 bit Session Key and 128 bit Initialisation Vector (iv) are created.

These are used to AES256-CBC encrypt the plaintext.

If the size of the plaintext is not a multiple of 128 bits (16 bytes) padding is added as required by AES.

### RSA

The Receiver Public Key is used to RSA encrypt the above Session Key.

The output ciphertext is a combination of (Encrypted Message + Encrypted Session Key + iv)
