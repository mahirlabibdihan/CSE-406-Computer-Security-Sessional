
import copy

def string_to_hex_space_separated(input_string):
    return " ".join(format(ord(char), "02x") for char in input_string)

def print_key(key):
    print()
    print("Key:")
    print("In ASCII: ", key)
    print("In HEX: ", string_to_hex_space_separated(key))

def print_iv(iv):
    print()
    print("IV:")
    print("In ASCII: ", iv)
    print("In HEX: ", string_to_hex_space_separated(iv))
    
def print_plain(plain):
    print()
    print("Plain Text:")
    print("In ASCII: ", plain)
    print("In HEX: ", string_to_hex_space_separated(plain))
    
def print_cipher(cipher):
    print()
    print("Cipher Text:")
    print("In HEX: ", string_to_hex_space_separated(cipher))
    print("In ASCII: ", copy.copy(cipher).encode('ascii', 'replace'))

def print_decipher(decipher):
    print()
    print("Deciphered Text:")
    print("In HEX: ", string_to_hex_space_separated(decipher))
    print("In ASCII: ", decipher)

def print_times(key_scheduling_time, encryption_time, decryption_time):
    print()
    print("Execution time details")
    print("Key Scheduling: ", key_scheduling_time * 1000, " ms")
    print("Encryption time: ", encryption_time * 1000, " ms")
    print("Decryption time: ", decryption_time * 1000, " ms")
