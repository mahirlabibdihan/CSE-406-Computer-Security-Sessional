from aes_ecb import *
from aes_cbc import *
from bonus_3_aes import *
import time

def string_to_hex_space_separated(input_string):
    return " ".join(format(ord(char), "02x") for char in input_string)

key="BUET CSE19 Batch"
msg="Never Gonna Give you up"
# iv = os.urandom(16)
nonce = secrets.randbits(128)
cipher = AES_CTR(key,nonce, 128)
cipher.keySchedule()

start_time = time.time()
key_schedule = cipher.keySchedule()
key_scheduling_time = time.time() - start_time

start_time = time.time()
encrypted_text = cipher.encrypt(msg)
encryption_time = time.time() - start_time

start_time = time.time()
decrypted_text = cipher.decrypt(encrypted_text)
decryption_time = time.time() - start_time

print("Key:")
print("In ASCII: ", cipher.adjustKey(key))
print("In HEX: ", string_to_hex_space_separated(cipher.adjustKey(key)))

print()
print("Plain Text:")
print("In ASCII: ", cipher.pad(msg))
print("In HEX: ", string_to_hex_space_separated(cipher.pad(msg)))

print()
print("Cipher Text:")
print("In HEX: ", string_to_hex_space_separated(encrypted_text))
print("In ASCII: ", encrypted_text)

print()
print("Deciphered Text:")
print("In HEX: ", string_to_hex_space_separated(decrypted_text))
print("In ASCII: ", decrypted_text)

print()
print("Execution time details")
print("Key Scheduling: ", key_scheduling_time*1000, " ms")
print("Encryption time: ", encryption_time*1000, " ms")
print("Decryption time: ", decryption_time*1000, " ms")