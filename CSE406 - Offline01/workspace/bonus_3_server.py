import socket
from task_2_ecc import *
from bonus_3_aes import *
import numpy as np
import pickle
import base64
import time
import threading
from logger import *


def config(client_socket):
    ecc = ECC()
    AES_LEN = 128

    [G, a, b, p] = ecc.generate_shared_parameters(AES_LEN)

    key_pr = random.randint(1, p - 1)
    A_key = ecc.scalar_multiply(key_pr, G, a, p)

    nonce = random.randint(2**(AES_LEN-1), 2**(AES_LEN) - 1)
    obj = {
        'AES_LEN': AES_LEN,
        'G': G,
        'a': a,
        'p': p,
        'nonce': nonce,
        'A_key': A_key
    }

    client_socket.sendall(pickle.dumps(obj))

    
    B_key = pickle.loads(client_socket.recv(1024))

    R_key = ecc.scalar_multiply(key_pr, B_key, a, p)

    return [R_key[0], nonce, AES_LEN]


def transmission(client_socket, cipher):
    print()
    start = time.time()
    print_log("Ready for file transmission", start)

    file_path = FILE_DIR+'/input.txt'
    bit_string = file_to_bit_string(file_path)
    msg_len: int = len(bit_string)
    client_socket.sendall(pickle.dumps(msg_len))
    print_log("Sent message length", start)

    encrypted_text = cipher.encrypt(bit_string)
    print_log("Encryption successful", start)
    client_socket.sendall(pickle.dumps(encrypted_text))
    print_log("Sent cipher text", start)


def handle_client(client_socket):
    [key, nonce, AES_LEN] = config(client_socket)
    cipher = setupCipher(key, nonce, AES_LEN)
    transmission(client_socket, cipher)


def establishConnection(server_socket):
    client_socket, addr = server_socket.accept()
    print('Got connection from', addr)

    client_handler = threading.Thread(
        target=handle_client, args=(client_socket,))
    client_handler.start()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")
    server_socket.bind(('localhost', 0))
    _, port = server_socket.getsockname() 
    print("socket binded to %s" % (port))
    server_socket.listen()
    print("socket is listening")

    while True:
        establishConnection(server_socket)

FILE_DIR = input("File Directory: ")
if __name__ == "__main__":
    main()
