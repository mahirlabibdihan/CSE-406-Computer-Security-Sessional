from bonus_3_aes import *
import time
from performance import *

FILE_DIR = input("File Directory: ")

AES_LEN = 128
key = "Thats my Kung Fu"
msg = file_to_bit_string(FILE_DIR+'/sample.jpg')
nonce = secrets.randbits(128)
cipher = AES_CTR(key, nonce, AES_LEN)

start_time = time.time()
key_schedule = cipher.key_expansion()
key_scheduling_time = time.time() - start_time

start_time = time.time()
encrypted_text = cipher.encrypt(msg)
encryption_time = time.time() - start_time

start_time = time.time()
decrypted_text = cipher.decrypt(encrypted_text)
decryption_time = time.time() - start_time

file_path = FILE_DIR+'/sample_out.jpg'
with open(file_path, 'wb') as output_file:
    for byte in decrypted_text:
        output_file.write(bytes([ord(byte)]))


print_key(cipher.adjust_key(key, AES_LEN//8))
# print_plain(cipher.pad(msg))
# print_cipher(encrypted_text)
# print_decipher(decrypted_text)
print_times(key_scheduling_time, encryption_time, decryption_time)