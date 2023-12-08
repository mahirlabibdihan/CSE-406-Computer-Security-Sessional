from task_1_aes import *
from performance import *
import time

AES_LEN = 128
key = "BUET CSE19 Batch"
msg = "Never Gonna Give you up"
iv = "0123456789ABCDEF"

cipher = AES_CBC(key, AES_LEN)

start_time = time.time()
key_schedule = cipher.key_expansion()
key_scheduling_time = time.time() - start_time

start_time = time.time()
encrypted_text = cipher.encrypt(msg, iv)
encryption_time = time.time() - start_time

start_time = time.time()
decrypted_text = cipher.decrypt(encrypted_text)
decryption_time = time.time() - start_time

print_key(cipher.adjust_key(key, AES_LEN//8))
print_iv(iv)
print_plain(cipher.pad(msg))
print_cipher(encrypted_text[16:])
print_decipher(cipher.pad(decrypted_text))
print_times(key_scheduling_time, encryption_time, decryption_time)
