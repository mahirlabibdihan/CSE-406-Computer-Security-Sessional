import socket
from task_2_ecc import *
from task_1_aes import *
import pickle
import time
import threading
import string
from performance import *

def binary_to_string(binary_string):
    return ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))


def aes_encryption(text, key, iv, AES_LEN):
    key = binary_to_string(bin(key)[2:])
    cipher = AES_CBC(key, AES_LEN)
    cipher.key_expansion()
    encrypted_text = cipher.encrypt(text, iv)
    return encrypted_text

def handle_client(client_socket):
    ecc = ECC()
    AES_LEN = 128
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
    R_key = ecc.scalar_multiply(key_pr, B_key, a, p)

    print("Shared key:",R_key[0])
    # print_key(binary_to_string(bin(R_key[0])[2:]))
    while True:
        iv = ''.join(random.choices(string.ascii_letters, k=16))
        text = "Never Gonna Give you up"
        print_plain(text)
        encrypted_text = aes_encryption(text, R_key[0], iv, AES_LEN)
        print_cipher(encrypted_text[16:])
        client_socket.sendall(pickle.dumps(encrypted_text))
        print("Text sent successfully")

        data = client_socket.recv(1024)
        if not data:
            print("Client disconnected")
            break


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


if __name__ == "__main__":
    main()
