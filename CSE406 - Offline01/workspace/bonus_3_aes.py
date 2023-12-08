import os
import numpy as np
from BitVector import *
from tables import *
from concurrent.futures import ProcessPoolExecutor
import secrets
import math
from bonus_1_aes import *


class AES_CTR(AES_CBC_EXTENDED):
    # key must be 128/192/256
    def __init__(self, key, nonce, aes_len):
        self.counter = 0
        self.nonce = nonce

        super().__init__(key, aes_len)

    def binary_to_array(self, binary_string):
        return np.array([int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8)], dtype=np.uint8)

    def block_cipher_cryption(self, keys, counter):
        random_text = int(self.nonce) + int(counter)
        random_text = bin(random_text)[2:]
        random_text = self.binary_to_array(random_text)

        block = random_text.reshape((4, 4))
        block = np.transpose(block)  # Column major
        crypted = self.aes_rounds(block, keys)
        crypted = np.transpose(crypted).flatten()

        return crypted

    def block_cipher(self, data_len, keys):
        with ProcessPoolExecutor() as executor:
            n_blocks = math.ceil(data_len/16)
            encrypted_blocks = list(executor.map(self.block_cipher_cryption, [
                                    keys] * n_blocks, range(n_blocks)))

            ciphertext = ""
            for crypted_block in encrypted_blocks:
                for char in crypted_block:
                    ciphertext += chr(char)

        self.counter += n_blocks
        return ciphertext

    def xor_strings(self, str1, str2):
        min_len = min(len(str1), len(str2))
        result = ""
        for char1, char2 in zip(str1[:min_len], str2[:min_len]):
            result += chr(ord(char1) ^ ord(char2))
        return result

    def start_encrypt(self, msg_len):
        return self.block_cipher(msg_len, self.all_keys)

    def end_encrypt(self, plain_text, xor_text):
        return self.xor_strings(xor_text, plain_text)

    def encrypt(self, plain_text):
        return self.end_encrypt(plain_text, self.start_encrypt(len(plain_text)))

    def start_decrypt(self, msg_len):
        return self.block_cipher(msg_len, self.all_keys)

    def end_decrypt(self, cipher_text, xor_text):
        return self.xor_strings(xor_text, cipher_text)

    def decrypt(self, cipher_text):
        return self.end_decrypt(cipher_text, self.start_decrypt(len(cipher_text)))


def file_to_bit_string(file_path):
    bit_string = ""
    with open(file_path, 'rb') as file:
        byte = file.read(1)
        while byte:
            bit_string += chr(ord(byte))
            byte = file.read(1)
    return bit_string


def binary_to_string(binary_string):
    return ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))


def setupCipher(key, nonce, AES_LEN):
    key = binary_to_string(bin(key)[2:])  # AES_LEN bits
    cipher = AES_CTR(key, nonce, AES_LEN)
    cipher.key_expansion()
    return cipher


def encryptText(cipher):
    plain_text = "Never Gonna Give you upNever Gonna Give you up"
    encrypted_text = cipher.encrypt(plain_text)
    print("Text", cipher.string_to_hex_space_separated(plain_text))
    print("Cipher", cipher.string_to_hex_space_separated(encrypted_text))
    print("iv", format(cipher.nonce,"02x"))
    return encrypted_text


def decryptText(cipher, encrypted_text):
    decrypted_text = cipher.decrypt(encrypted_text)
    print("Plain text:", decrypted_text)
    


def encryptFile(cipher):
    file_path = 'sample.jpg'
    plain_text = file_to_bit_string(file_path)
    cipher_text = cipher.encrypt(plain_text)
    print("Cipher text:", cipher_text)

    
    return cipher_text


def decryptFile(cipher, encrypted_text):
    decrypted_text = cipher.decrypt(encrypted_text)
    file_path = 'sample_out.jpg'
    with open(file_path, 'wb') as output_file:
        for byte in decrypted_text:
            output_file.write(bytes([ord(byte)]))


def main():
    AES_LEN = 256
    key = "Thats my Kung FuThats my Kung Fu"
    
    cipher = AES_CTR(key, 2**127, AES_LEN)
    cipher.key_expansion()

    print("Key", cipher.string_to_hex_space_separated(key))
    
    decryptText(cipher, encryptText(cipher))
    # decryptFile(cipher, encryptFile(cipher))

FILE_DIR = "."
if __name__ == "__main__":
    main()


