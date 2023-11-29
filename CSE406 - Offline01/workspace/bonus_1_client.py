import socket
from bonus_1 import *
from elliptic_curve import *
import pickle
import base64
import time

def binary_to_string(binary_string):
    return ' '.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))


def AES_DECRYPTION(text, key, iv, AES_LEN):
    key = binary_to_string(bin(key)[2:])  # AES_LEN bits
    iv = binary_to_string(bin(iv)[2:]) 
    cipher = GENERIC_AES_CBC(key, AES_LEN)
    cipher.keySchedule()
    decrypted_text = cipher.decrypt(text, iv)
    return decrypted_text


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 12346
    s.connect(('127.0.0.1', port))
    print('Connected to', '127.0.0.1 :', port)
    obj = pickle.loads(s.recv(4096))

    AES_LEN = obj['AES_LEN']
    G = obj['G']
    a = obj['a']
    p = obj['p']
    A_iv = obj['A_iv']
    A_key = obj['A_key']

    key_pr = random.randint(1, p - 1)
    iv_pr = random.randint(1, p - 1)
    
    R_key = scalarMultiply(key_pr, A_key, a, p)
    R_iv = scalarMultiply(iv_pr, A_iv, a, p)
    
    B_key = scalarMultiply(key_pr, G, a, p)
    B_iv = scalarMultiply(iv_pr, G, a, p)

    obj = {
        'B_iv': B_iv,
        'B_key': B_key
    }
    
    s.sendall(pickle.dumps(obj))

    start = time.time()
    encrypted_text = pickle.loads(s.recv(4096))

    print("File received successfully :", (time.time()-start), "seconds")

    start = time.time()
    decrypted_text = AES_DECRYPTION(encrypted_text, R_key[0], R_iv[0], AES_LEN)
    print("File decrypted successfully :", (time.time()-start), "seconds")
    file_path = 'sample_out.jpg'
    with open(file_path, 'wb') as output_file:
        for byte in decrypted_text:
            output_file.write(bytes([ord(byte)]))
    s.close()


if __name__ == "__main__":
    main()
