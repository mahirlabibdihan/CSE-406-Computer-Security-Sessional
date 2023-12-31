import socket
from bonus_1_aes import *
from task_2_ecc import *
import pickle
import time



def binary_to_string(binary_string):
    return ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))


def aes_decryption(text, key, AES_LEN):
    key = binary_to_string(bin(key)[2:]) 
    cipher = AES_CBC_EXTENDED(key, AES_LEN)
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

    start = time.time()
    encrypted_text = pickle.loads(s.recv(4096))
    print("File received successfully :", (time.time()-start), "seconds")
    
    start = time.time()
    decrypted_text = aes_decryption(
        encrypted_text[16:], R_key[0], AES_LEN)

    print("File decrypted successfully :", (time.time()-start), "seconds")

    file_path = FILE_DIR+'sample_out.jpg'
    with open(file_path, 'wb') as output_file:
        for byte in decrypted_text:
            output_file.write(bytes([ord(byte)]))

    s.close()

if __name__ == "__main__":
    FILE_DIR = input("File Directory: ")
    main()

