import os
import numpy as np
from BitVector import *
from tables import *
from task_1_aes import *
import math


class AES_CBC_EXTENDED(AES_CBC):
    # PKCS #7 padding
    def pad(self, data):
        width = 16
        if (len(data) % (width) == 0):
            for i in range(width):
                data += chr(0)

        else:
            need = (width) - len(data) % (width)
            while len(data) % (width) != 0:
                data += chr(need)
        return data

    def unpad(self, data):
        width = 16
        flag = True
        for i in range(len(data)-width, len(data)):
            if (ord(data[i]) != 0):
                flag = False
                break
        if flag:
            return ''.join(data[i] for i in range(len(data)-width))
        else:
            return ''.join(data[i] for i in range(len(data)-ord(data[-1])))


def file_to_bit_string(file_path):
    bit_string = ""
    with open(file_path, 'rb') as file:
        byte = file.read(1)
        while byte:
            bit_string += chr(ord(byte))
            byte = file.read(1)
    return bit_string


def encryptFile(cipher, iv):
    file_path = FILE_DIR+'/sample.jpg'
    print("Encrypting file:", file_path)
    plain_text = file_to_bit_string(file_path)
    cipher_text = cipher.encrypt(plain_text, iv)
    print("File encrypted successfully")
    return cipher_text


def decryptFile(cipher, encrypted_text):
    decrypted_text = cipher.decrypt(encrypted_text)
    print("File decrypted successfully")
    file_path = FILE_DIR+'/sample_out.jpg'
    with open(file_path, 'wb') as output_file:
        for byte in decrypted_text:
            output_file.write(bytes([ord(byte)]))
    print("File saved as:",file_path)


def main():
    AES_LEN = 256
    iv = "0123456789ABCDEF"
    key = "Thats my Kung Fu"
    cipher = AES_CBC_EXTENDED(key, AES_LEN)
    cipher.key_expansion()
    decryptFile(cipher, encryptFile(cipher, iv))

FILE_DIR = "."
if __name__ == "__main__":
    FILE_DIR = input("File Directory: ")
    main()
