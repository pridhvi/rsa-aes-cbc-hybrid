# RSA AES-CBC Hybrid Encryption

An implementation of a hybrid encryption system involving RSA, AES256-CBC

## Requirements

1. Receiver public and private keys (RSA keys in pem or der format)
2. Sender public and private keys (RSA keys in pem or der format)
3. Input plaintext file which is to be encrypted

## Encrypt command

`python3 fcrypt.py -e <receiver_public_key_file> <sender_private_key_file> <input_plaintext_file> <output_ciphertext_file>`

## Decrypt command

`python3 fcrypt.py -d <receiver_private_key_file> <sender_public_key_file> <input_ciphertext_file> <output_plaintext_file>`


## Encryption Process

1. Random 256-bit session key and 128-bit Initialisation Vector are generated.
2. The session key and iv are used to encrypt the plaintext.
3. The encrypted plaintext is digitally signed using the sender’s private key.
4. The session key is encrypted using receivers public key.
5. The final output is a package is made of (encrypted message + encrypted session_key + iv + signature)

## Decryption Process

1. The encrypted is package is split into the separate values.
2. The digital signature is verified using sender’s public key and if the verification fails the
program is aborted before the decryption is done.
3. The encrypted session key is decrypted using receiver’s private key.
4. The encrypted message is decrypted using the session key.
