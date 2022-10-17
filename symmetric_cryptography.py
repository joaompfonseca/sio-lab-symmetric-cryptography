import argparse
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# Auxiliar Functions

def binary_from_bmp(fname: str):
    file = open(fname, 'rb')
    header = file.read(54)
    binary = file.read()
    file.close()
    return binary, header


def binary_to_bmp(fname: str, binary: bytes, header: bytes):
    file = open(fname, 'wb')
    file.write(header)
    file.write(binary)
    file.close()


def binary_from_file(fname: str):
    file = open(fname, 'rb')
    binary = file.read()
    file.close()
    return binary


def binary_to_file(fname: str, binary: bytes):
    file = open(fname, 'wb')
    file.write(binary)
    file.close()


def generate_bytes(nbytes: int):
    return secrets.token_bytes(nbytes)


# Exercise Functions

def file_encryption_AES(file_to_encrypt: str, file_to_store: str, mode: str):  # Advanced Encryption Standard
    if file_to_encrypt.endswith('.bmp'):
        text, header = binary_from_bmp(file_to_encrypt)
    else:
        text = binary_from_file(file_to_encrypt)

    key = generate_bytes(32)
    iv = generate_bytes(16)  # Initialization Vector

    if mode == 'ECB':
        cipher_mode = modes.ECB()  # Doesn't use iv
    elif mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'CFB':
        cipher_mode = modes.CFB(iv)
    elif mode == 'OFB':
        cipher_mode = modes.OFB(iv)
    else:
        print(f'Unsupported cipher mode {mode}')
        return

    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=cipher_mode
    )

    padder = padding.PKCS7(16 * 8).padder()  # 16 bytes
    padded = padder.update(text) + padder.finalize()

    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded) + encryptor.finalize()

    if file_to_store.endswith('.bmp'):
        binary_to_bmp(file_to_store, cipher_text, header)
    else:
        binary_to_file(file_to_store, cipher_text)

    print(f'Algorithm: AES')
    print(f'Cipher Mode: {cipher_mode.name}')
    print(f'Key: {key.hex()}')
    if mode != 'ECB':
        print(f'Initialization Vector: {iv.hex()}')
    print(f'Text ({len(text) / 8} B): {text[:50]}...')
    print(f'Padded ({len(padded) / 8} B): {padded[:50]}...')
    print(f'Cipher ({len(cipher_text) / 8} B): {cipher_text[:50]}...')


def file_encryption_ChaCha20(file_to_encrypt: str, file_to_store: str):
    if file_to_encrypt.endswith('.bmp'):
        text, header = binary_from_bmp(file_to_encrypt)
    else:
        text = binary_from_file(file_to_encrypt)

    key = generate_bytes(32)
    nonce = generate_bytes(16)  # Should be only used once with the same key (thus N-Once)

    cipher = Cipher(
        algorithm=algorithms.ChaCha20(key, nonce),
        mode=None
    )

    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(text) + encryptor.finalize()

    if file_to_store.endswith('.bmp'):
        binary_to_bmp(file_to_store, cipher_text, header)
    else:
        binary_to_file(file_to_store, cipher_text)

    print(f'Algorithm: ChaCha20')
    print(f'Key: {key.hex()}')
    print(f'Nonce: {nonce.hex()}')
    print(f'Text ({len(text) / 8} B): {text[:50]}...')
    print(f'Cipher ({len(cipher_text) / 8} B): {cipher_text[:50]}...')


def file_decryption_AES(file_to_decrypt: str, file_to_store: str, mode: str, key: bytes, iv: bytes):
    if file_to_decrypt.endswith('.bmp'):
        cipher_text, header = binary_from_bmp(file_to_decrypt)
    else:
        cipher_text = binary_from_file(file_to_decrypt)

    if mode == 'ECB':
        cipher_mode = modes.ECB()  # Doesn't use iv
    elif mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'CFB':
        cipher_mode = modes.CFB(iv)
    elif mode == 'OFB':
        cipher_mode = modes.OFB(iv)
    else:
        print(f'Unsupported cipher mode {mode}')
        return

    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=cipher_mode
    )

    decryptor = cipher.decryptor()
    padded = decryptor.update(cipher_text) + decryptor.finalize()

    unpadder = padding.PKCS7(16 * 8).unpadder()  # 16 bytes
    text = unpadder.update(padded) + unpadder.finalize()

    if file_to_store.endswith('.bmp'):
        binary_to_bmp(file_to_store, text, header)
    else:
        binary_to_file(file_to_store, text)

    print(f'Algorithm: AES')
    print(f'Cipher Mode: {cipher_mode.name}')
    print(f'Key: {key.hex()}')
    if mode != 'ECB':
        print(f'Initialization Vector: {iv.hex()}')
    print(f'Cipher ({len(cipher_text) / 8} B): {cipher_text[:50]}...')
    print(f'Padded ({len(padded) / 8} B): {padded[:50]}...')
    print(f'Text ({len(text) / 8} B): {text[:50]}...')


def file_decryption_ChaCha20(file_to_decrypt: str, file_to_store: str, key: bytes, nonce: bytes):
    if file_to_decrypt.endswith('.bmp'):
        cipher_text, header = binary_from_bmp(file_to_decrypt)
    else:
        cipher_text = binary_from_file(file_to_decrypt)

    cipher = Cipher(
        algorithm=algorithms.ChaCha20(key, nonce),
        mode=None
    )

    decryptor = cipher.decryptor()
    text = decryptor.update(cipher_text) + decryptor.finalize()

    if file_to_store.endswith('.bmp'):
        binary_to_bmp(file_to_store, text, header)
    else:
        binary_to_file(file_to_store, text)

    print(f'Algorithm: ChaCha20')
    print(f'Key: {key.hex()}')
    print(f'Nonce: {nonce.hex()}')
    print(f'Cipher ({len(cipher_text) / 8} B): {cipher_text[:50]}...')
    print(f'Text ({len(text) / 8} B): {text[:50]}...')


# Main Function

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='action', help='The action to perform', required=True)
    #
    # File Encryption
    #
    encrypt = subparsers.add_parser('encrypt')
    encrypt.add_argument('file_to_encrypt', type=str, help='The name of the file to encrypt')
    encrypt.add_argument('file_to_store', type=str, help='The name of the file to store the cryptogram')
    encrypt_subparsers = encrypt.add_subparsers(dest='algorithm', help='The name of the encryption algorithm',
                                                required=True)
    # AES
    encrypt_AES = encrypt_subparsers.add_parser('AES')
    encrypt_AES.add_argument('mode', type=str, choices=['ECB', 'CBC', 'CFB', 'OFB'],
                             help='The name of the cipher mode')
    # ChaCha20
    encrypt_ChaCha20 = encrypt_subparsers.add_parser('ChaCha20')
    #
    # File Decryption
    #
    decrypt = subparsers.add_parser('decrypt')
    decrypt.add_argument('file_to_decrypt', type=str, help='The name of the file to decrypt')
    decrypt.add_argument('file_to_store', type=str, help='The name of the file to store the text')
    decrypt_subparsers = decrypt.add_subparsers(dest='algorithm', help='The name of the encryption algorithm',
                                                required=True)
    # AES
    decrypt_AES = decrypt_subparsers.add_parser('AES')
    decrypt_AES_subparsers = decrypt_AES.add_subparsers(dest='mode', help='The name of the cipher mode', required=True)
    # AES with ECB (Electronic Codebook)
    decrypt_AES_ECB = decrypt_AES_subparsers.add_parser('ECB')
    decrypt_AES_ECB.add_argument('key', type=str, help='The 32 byte key (in hex) used in the encryption')
    # AES with CBC (Cipher Block Chaining)
    decrypt_AES_CBC = decrypt_AES_subparsers.add_parser('CBC')
    decrypt_AES_CBC.add_argument('key', type=str, help='The 32 byte key (in hex) used in the encryption')
    decrypt_AES_CBC.add_argument('iv', type=str,
                                 help='The 16 byte initialization vector (in hex) used in the encryption')
    # AES with CFB (Cipher Feedback)
    decrypt_AES_CFB = decrypt_AES_subparsers.add_parser('CFB')
    decrypt_AES_CFB.add_argument('key', type=str, help='The 32 byte key (in hex) used in the encryption')
    decrypt_AES_CFB.add_argument('iv', type=str,
                                 help='The 16 byte initialization vector (in hex) used in the encryption')
    # AES with OFB (Output Feedback)
    decrypt_AES_OFB = decrypt_AES_subparsers.add_parser('OFB')
    decrypt_AES_OFB.add_argument('key', type=str, help='The 32 byte key (in hex) used in the encryption')
    decrypt_AES_OFB.add_argument('iv', type=str,
                                 help='The 16 byte initialization vector (in hex) used in the encryption')
    # ChaCha20
    decrypt_ChaCha20 = decrypt_subparsers.add_parser('ChaCha20')
    decrypt_ChaCha20.add_argument('key', type=str, help='The 32 byte key (in hex) used in the encryption')
    decrypt_ChaCha20.add_argument('nonce', type=str, help='The 16 byte nonce (in hex) used in the encryption')

    args = parser.parse_args()

    if args.action == 'encrypt' and args.algorithm == 'AES':
        file_encryption_AES(
            args.file_to_encrypt,
            args.file_to_store,
            args.mode
        )
    if args.action == 'encrypt' and args.algorithm == 'ChaCha20':
        file_encryption_ChaCha20(
            args.file_to_encrypt,
            args.file_to_store
        )
    if args.action == 'decrypt' and args.algorithm == 'AES':
        file_decryption_AES(
            args.file_to_decrypt,
            args.file_to_store,
            args.mode,
            bytes.fromhex(args.key),
            bytes.fromhex(args.iv) if 'iv' in args else None
        )
    if args.action == 'decrypt' and args.algorithm == 'ChaCha20':
        file_decryption_ChaCha20(
            args.file_to_decrypt,
            args.file_to_store,
            bytes.fromhex(args.key),
            bytes.fromhex(args.nonce)
        )


if __name__ == "__main__":
    main()
