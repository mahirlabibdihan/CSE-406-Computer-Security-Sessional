import socket
from bonus_3_aes import *
from elliptic_curve import *
import pickle
import base64
import time

def binary_to_string(binary_string):
    return ' '.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))


def AES_DECRYPTION(text, key, nonce, AES_LEN):
    key = binary_to_string(bin(key)[2:])  # AES_LEN bits
    cipher = AES_CTR(key, nonce, AES_LEN)
    cipher.keySchedule()
    decrypted_text = cipher.decrypt(text)
    return decrypted_text


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 12345
    s.connect(('127.0.0.1', port))
    print('Connected to', '127.0.0.1 :', port)
    obj = pickle.loads(s.recv(4096))

    AES_LEN = obj['AES_LEN']
    G = obj['G']
    a = obj['a']
    p = obj['p']
    A_nonce = obj['A_nonce']
    A_key = obj['A_key']

    key_pr = random.randint(1, p - 1)
    nonce_pr = random.randint(1, p - 1)
    
    R_key = scalarMultiply(key_pr, A_key, a, p)
    R_nonce = scalarMultiply(nonce_pr, A_nonce, a, p)
    
    B_key = scalarMultiply(key_pr, G, a, p)
    B_nonce = scalarMultiply(nonce_pr, G, a, p)

    obj = {
        'B_nonce': B_nonce,
        'B_key': B_key
    }
    
    s.sendall(pickle.dumps(obj))

    start = time.time()
    encrypted_text = pickle.loads(s.recv(4096))

    print("File received successfully :", (time.time()-start), "seconds")

    start = time.time()
    decrypted_text = AES_DECRYPTION(encrypted_text, R_key[0], R_nonce[0], AES_LEN)
    print("File decrypted successfully :", (time.time()-start), "seconds")
    file_path = 'sample_out.jpg'
    with open(file_path, 'wb') as output_file:
        for byte in decrypted_text:
            output_file.write(bytes([ord(byte)]))
    s.close()


if __name__ == "__main__":
    main()
