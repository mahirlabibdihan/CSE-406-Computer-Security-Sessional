import socket
from bonus_3_aes import *
from task_2_ecc import *
import pickle
import base64
import time
from logger import *


def config(s):
    obj = pickle.loads(s.recv(4096))
    AES_LEN = obj['AES_LEN']
    G = obj['G']
    a = obj['a']
    p = obj['p']
    nonce = obj['nonce']
    A_key = obj['A_key']

    print("Shared nonce:", nonce)
    print("Public key:", A_key)

    key_pr = random.randint(1, p - 1)
    print("Private key:", key_pr)

    ecc = ECC()
    R_key = ecc.scalar_multiply(key_pr, A_key, a, p)
    B_key = ecc.scalar_multiply(key_pr, G, a, p)

    print("Shared key:", R_key[0])
    s.sendall(pickle.dumps(B_key))
    return [R_key[0], nonce, AES_LEN]


def transmission(s, cipher):
    print()
    start = time.time()
    print_log("Ready for file transmission", start)
    msg_len = pickle.loads(s.recv(28))
    print_log("Received message length", start)
    xor_text = cipher.start_decrypt(msg_len)
    print_log("Ready to decrypt", start)
    encrypted_text = pickle.loads(s.recv(4096))
    print_log("File received", start)
    decrypted_text = cipher.end_decrypt(encrypted_text, xor_text)
    print_log("Decryption successful", start)

    file_path = FILE_DIR+'/output.txt'
    with open(file_path, 'wb') as output_file:
        for byte in decrypted_text:
            output_file.write(bytes([ord(byte)]))
    s.close()
    print_log("File saved as: " + file_path, start)


def establishConnection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Enter server port:", end=' ')
    port = int(input())
    s.connect(('127.0.0.1', port))
    print('Connected to', '127.0.0.1 :', port)
    return s


def main():
    socket = establishConnection()
    [key, nonce, AES_LEN] = config(socket)
    cipher = setupCipher(key, nonce, AES_LEN)
    transmission(socket, cipher)

FILE_DIR = input("File Directory: ")
if __name__ == "__main__":
    main()
