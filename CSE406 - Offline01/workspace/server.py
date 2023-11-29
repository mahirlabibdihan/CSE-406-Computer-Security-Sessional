import socket
from elliptic_curve import *
from bonus_1 import *
import numpy as np
import pickle
import base64
import time


def binary_to_string(binary_string):
    return ' '.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))


def AES_ENCRYPTION(text, key, iv, AES_LEN):
    key = binary_to_string(bin(key)[2:])  # AES_LEN bits
    iv = binary_to_string(bin(iv)[2:]) 
    cipher = GENERIC_AES_CBC(key, AES_LEN)
    cipher.keySchedule()
    encrypted_text = cipher.encrypt(text, iv)
    return encrypted_text


def file_to_bit_string(file_path):
    bit_string = ""
    with open(file_path, 'rb') as file:
        byte = file.read(1)
        while byte:
            bit_string += chr(ord(byte))
            byte = file.read(1)
    return bit_string


def main():
    # AF_INET refers to the address-family ipv4.
    # The SOCK_STREAM means connection-oriented TCP protocol.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")

    # reserve a port on your computer in our
    # case it is 12345 but it can be anything
    port = 12345
    AES_LEN = 128
    s.bind(('', port))
    print("socket binded to %s" % (port))

    s.listen()
    print("socket is listening")

    while True:
        # Establish connection with client.
        c, addr = s.accept()
        print('Got connection from', addr)
        # iv = os.urandom(16)   # 128-bit IV

        [G, a, b, p] = generate_shared_parameters(AES_LEN)

        key_pr = random.randint(1, p - 1)
        A_key = scalarMultiply(key_pr, G, a, p)
        
        iv_pr = random.randint(1, p - 1)
        A_iv = scalarMultiply(iv_pr, G, a, p)

        obj = {
            'AES_LEN': AES_LEN,
            'G': G,
            'a': a,
            'p': p,
            'A_iv': A_iv,
            'A_key': A_key
        }

        c.sendall(pickle.dumps(obj))

        obj = pickle.loads(c.recv(1024))
        B_key = obj['B_key']
        B_iv = obj['B_iv']
        
        R_key = scalarMultiply(key_pr, B_key, a, p)
        R_iv = scalarMultiply(iv_pr, B_iv, a, p)

        text = "Never Gonna Give you up"
        start = time.time()
        encrypted_text = AES_ENCRYPTION(text, R_key[0], R_iv[0], AES_LEN)
        print("File encrypted successfully : ", (time.time()-start), "seconds")
        c.sendall(pickle.dumps(encrypted_text))
        print("File sent successfully")

        c.close()


if __name__ == "__main__":
    main()
