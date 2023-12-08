import socket
from task_1_aes import *
from task_2_ecc import *
import pickle
from performance import *

def binary_to_string(binary_string):
    return ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))


def aes_decryption(text, key, AES_LEN):
    key = binary_to_string(bin(key)[2:])
    cipher = AES_CBC(key, AES_LEN)
    cipher.key_expansion()
    decrypted_text = cipher.decrypt(text)
    return decrypted_text


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print("Enter server port:", end=' ')
    port = int(input())
    s.connect(('127.0.0.1', port))
    print('Connected to', '127.0.0.1 :', port)
    obj = pickle.loads(s.recv(4096))

    AES_LEN = obj['AES_LEN']
    G = obj['G']
    a = obj['a']
    p = obj['p']
    A_key = obj['A_key']

    key_pr = random.randint(1, p - 1)

    ecc = ECC()
    R_key = ecc.scalar_multiply(key_pr, A_key, a, p)
    B_key = ecc.scalar_multiply(key_pr, G, a, p)

    print("Shared key: ", R_key[0])

    s.sendall(pickle.dumps(B_key))

    for i in range(5):
        encrypted_text = pickle.loads(s.recv(4096))

        print_cipher(encrypted_text[16:])
        decrypted_text = aes_decryption(
            encrypted_text, R_key[0], AES_LEN)
        print_decipher(decrypted_text)

        s.send("ACK".encode('utf-8'))
    s.close()


if __name__ == "__main__":
    main()
