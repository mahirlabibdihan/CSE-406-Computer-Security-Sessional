import socket
from task_2_ecc import *
from bonus_1_aes import *
import numpy as np
import pickle
import base64
import time
import threading
import string


def binary_to_string(binary_string):
    return ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))


def aes_encryption(text, key, iv, AES_LEN):
    key = binary_to_string(bin(key)[2:])
    cipher = AES_CBC_EXTENDED(key, AES_LEN)
    cipher.key_expansion()
    encrypted_text = cipher.encrypt(text, iv)
    return encrypted_text


AES_LEN = 128


def handle_client(client_socket):
    ecc = ECC()
    [G, a, b, p] = ecc.generate_shared_parameters(AES_LEN)

    key_pr = random.randint(1, p - 1)
    A_key = ecc.scalar_multiply(key_pr, G, a, p)

    obj = {
        'AES_LEN': AES_LEN,
        'G': G,
        'a': a,
        'p': p,
        'A_key': A_key
    }

    client_socket.sendall(pickle.dumps(obj))

    B_key = pickle.loads(client_socket.recv(1024))

    A_key = ecc.scalar_multiply(key_pr, G, a, p)
    R_key = ecc.scalar_multiply(key_pr, B_key, a, p)

    iv = ''.join(random.choices(string.ascii_letters, k=16))

    file_path = FILE_DIR+'/sample.jpg'
    bit_string = file_to_bit_string(file_path)

    start = time.time()
    encrypted_text = aes_encryption(bit_string, R_key[0], iv, AES_LEN)
    print("File encrypted successfully : ", (time.time()-start), "seconds")
    client_socket.sendall(pickle.dumps(iv+encrypted_text))
    print("File sent successfully")


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")

    s.bind(('localhost', 0))
    _, port = s.getsockname() 
    print("socket binded to %s" % (port))

    s.listen()
    print("socket is listening")

    while True:
        client_socket, addr = s.accept()
        print('Got connection from', addr)
        client_handler = threading.Thread(
            target=handle_client, args=(client_socket,))
        client_handler.start()

FILE_DIR = input("File Directory: ")
if __name__ == "__main__":
    main()

