
from BitVector import *
import time
import numpy as np
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

def print_bitvector_matrix(key):
    for i in range(len(key)):
        print("word ",i+1,end=": ")
        for j in range(len(key[i])):
            print(key[i][j].get_bitvector_in_hex(),end=" ")
        print()
    print()

def print_bitvector_array(key):
    for bv in key:
        print(bv.get_bitvector_in_hex(),end=" ")
    print()
     
def to_hex(text):
    return [format(ord(char), '02x') for char in text]

def binary_to_hex_array(binary_string):
    hex_string = []
    for i in range(0,len(binary_string),8):
        hex_string.append(hex(int(binary_string[i:i+8],2))[2:])
    return hex_string

def pad(string,len):
    string = string[:len].ljust(len, '0')
    return binary_to_hex_array(string)

def transpose_matrix(matrix):
    return [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0]))]

def convert_to_2D_array(array):
    array_chunks = [array[i:i+4] for i in range(0, len(array), 4)]
    bitvector_array = [[BitVector(hexstring=chunk[j]) for chunk in array_chunks] for j in range(4)]
    transposed_array = transpose_matrix(bitvector_array)
    return transposed_array

ROUND_COUNT = {128 : 10, 192 : 12, 256 : 14}
AES_MODULUS = BitVector(bitstring='100011011')

def xor_list(list1, list2):
    return [a ^ b for a, b in zip(list1, list2)]

def xor_matrix(matrix1, matrix2):
    return [xor_list(row1, row2) for row1, row2 in zip(matrix1, matrix2)]

def left_rot_word(list,shift):
    shift = shift % len(list) # handle cases where the shift value is greater than the length of the list
    return list[shift:] + list[:shift]

def right_rot_word(list,shift):
    shift = shift % len(list) # handle cases where the shift value is greater than the length of the list
    return list[-shift:] + list[:-shift]


def sub_word(list,inv=False):
    sbox = InvSbox if inv else Sbox
    return [BitVector(intVal=sbox[bv.intValue()], size=8) for bv in list]


def func_g(word,round_constant):
    # one-byte left circular rotation
    word = left_rot_word(word,1)
    # substitute bytes
    word = sub_word(word)
    # XOR with round constant
    word[0] ^= round_constant
    return word


def key_scheduling(key,AES_LEN):
    all_keys = []
    key_round_0 = convert_to_2D_array(key)
    all_keys.append(key_round_0)
    # print("Round 0")
    # print_bitvector_matrix(key_round_0)
    COL = len(key_round_0)
    round_constant = BitVector(hexstring="01")
    for round in range(1,ROUND_COUNT[AES_LEN]+1):
        key_new_round = []
        key_new_round.append( xor_list(all_keys[round-1][0],func_g(all_keys[round-1][COL-1],round_constant)) )
        for i in range(1,len(all_keys[round-1])):
            key_new_round.append(xor_list(all_keys[round-1][i],key_new_round[i-1]))
        all_keys.append(key_new_round)
        # print("Round",round)
        # print_bitvector_matrix(key_new_round)
        round_constant = round_constant.gf_multiply_modular(BitVector(hexstring="02"),AES_MODULUS,8)

    # transpose all_keys
    all_keys = [transpose_matrix(key) for key in all_keys]
   
    return all_keys

def print_round(round):
    print()
    print("round ",round)

def sub_matrix(matrix,inv=False):
    for i in range(len(matrix)):
        matrix[i] = sub_word(matrix[i],inv)
    
    return matrix   

def left_rot_matrix(matrix):
    for i in range(len(matrix)):
        matrix[i] = left_rot_word(matrix[i],i)
    return matrix

def right_rot_matrix(matrix):
    for i in range(len(matrix)):
        matrix[i] = right_rot_word(matrix[i],i)
    return matrix

def mix_columns(matrix,inv=False):
    mixer = InvMixer if inv else Mixer
    
    ret = []
    for _ in range(len(matrix)):
        ret.append([BitVector(intVal=0, size=8)] * len(matrix[0]))
    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            for k in range(len(matrix)):
                ret[i][j] ^= (mixer[i][k].gf_multiply_modular(matrix[k][j],AES_MODULUS,8)) 
    
    return ret

def AES_ENCRYPT_ROUNDS(state,keys,AES_LEN):
    # print("Encrypt Round 0")
    # print_bitvector_matrix(state)

    print_bitvector_matrix(state)
    print_bitvector_matrix(keys[0])
    state = xor_matrix(state,keys[0])
    print_bitvector_matrix(state)
    # print_round(0)
    # print_bitvector_matrix(state)
    
    for round in range(1,ROUND_COUNT[AES_LEN]+1):
        # print_round(round)
        # print_bitvector_matrix(state)
        # substitute bytes
        state = sub_matrix(state)
        # print_bitvector_matrix(state)
        # shift rows
        state = left_rot_matrix(state)
        # print_bitvector_matrix(state)
        # mix columns
        if round != ROUND_COUNT[AES_LEN]:
            state = mix_columns(state)
            # print_bitvector_matrix(state)
        # add round key
        # print_bitvector_matrix(keys[round])
        state = xor_matrix(state,keys[round])
        # print_bitvector_matrix(state)
    

    return state

def AES_DECRYPT_ROUNDS(state,keys,AES_LEN):
    state = xor_matrix(state,keys[0])
    # print_round(0)
    # print_bitvector_matrix(state)
    
    for round in range(1,ROUND_COUNT[AES_LEN]+1):
        # print_round(round)
        
         # shift rows
        state = right_rot_matrix(state)
        # print_bitvector_matrix(state)
        # substitute bytes
        state = sub_matrix(state,True)
        # print_bitvector_matrix(state)
       
        # add round key
        state = xor_matrix(state,keys[round])
        # print_bitvector_matrix(state)
        # mix columns
        if round != ROUND_COUNT[AES_LEN]:
            state = mix_columns(state,True)
            # print_bitvector_matrix(state)
    return state


def convert_to_ascii(matrix):
    ascii_string = ""
    for i in range(0,len(matrix)):
        for j in range(0,len(matrix[i])):
            # print(matrix[i][j].get_bitvector_in_hex(),chr(int(matrix[i][j].get_bitvector_in_hex(),16)))
            ascii_string += chr(int(matrix[i][j].get_bitvector_in_hex(),16))
    return ascii_string

def flatten_matrix(matrix):
    list = []
    for row in matrix:
        for col in row:
            list.append(col.get_bitvector_in_hex())
    return list
    
def ENCRYPT_AES(AES_LEN,text,key):
    # key might not be of the required length, so resize it
    key = pad(key,AES_LEN)
    # AES key scheduling
    key_schedule = key_scheduling(key,AES_LEN)

    while( len(text)%(AES_LEN//8) != 0 ):
        text += "\0"
    
    encrypted_text = ""
    encrypted_hex = []

    start_time = time.time()

    for i in range(0,len(text),AES_LEN//8):
        split_text = text[i:i+AES_LEN//8]
        split_text = convert_to_2D_array(to_hex(split_text))
        split_text = transpose_matrix(split_text)
        encrypted = AES_ENCRYPT_ROUNDS(split_text,key_schedule,AES_LEN)

        encrypted = transpose_matrix(encrypted)
        # print_bitvector_matrix(encrypted)
        encrypted_text += convert_to_ascii(encrypted)
        encrypted_hex += flatten_matrix(encrypted)

    
    encryption_time = time.time() - start_time

    # print("Encrypted hex:",encrypted_hex_list)
    # print("Encrypted text:",encrypted_text_list)
    
    return encrypted_hex,encrypted_text,encryption_time

def to_binary(text):
    binary_string = ''.join(bin(ord(char))[2:].zfill(8) for char in text)
    return binary_string



def DECRYPT_AES(AES_LEN,text,key):
    # key might not be of the required length, so resize it
    key = pad(key,AES_LEN)
    # print(key)
    # AES key scheduling
    key_schedule = key_scheduling(key,AES_LEN)
    # print_bitvector_matrix(key_schedule[0])
    key_schedule = key_schedule[::-1]
  
    start_time = time.time()
    decrypted_text = ""
    decrypted_hex = []
    for i in range(0,len(text),AES_LEN//8):
        split_text = text[i:i+AES_LEN//8]
        split_text = convert_to_2D_array(to_hex(split_text))
        split_text = transpose_matrix(split_text)
        decrypted = AES_DECRYPT_ROUNDS(split_text,key_schedule,AES_LEN)
        decrypted = transpose_matrix(decrypted)
        decrypted_text += convert_to_ascii( decrypted )
        decrypted_hex += flatten_matrix(decrypted)

    decryption_time = time.time() - start_time
    # print("Decrypted hex:",decrypted_hex)
    # print("Decrypted text:",decrypted_text)
    
    return decrypted_hex,decrypted_text,decryption_time

def main():
    key = "BUET CSE19 Batch"
    text = "Never Gonna Give you up"
    AES_LEN = 128
    
    text_hex = to_hex(text)
    print(text_hex)
    key_hex = to_hex(key)
    # text_hex = ''.join(item for item in text_hex)

    key_bin = to_binary(key)
    print(key_bin)
    [encrypted_hex,encrypted_text,encryption_time] = ENCRYPT_AES(AES_LEN,text,key_bin)
    [decrypted_hex,decrypted_text,decryption_time] = DECRYPT_AES(AES_LEN,encrypted_text,key_bin)
    
    start_time = time.time()
    key_bin = pad(key_bin,AES_LEN)
    key_scheduled = key_scheduling(key_bin,AES_LEN)
    key_scheduling_time = time.time() - start_time

    print("Plain Text:")
    print("In ASCII: ",text)
    print("In HEX: ",*text_hex)
    print()
    print("Key:")
    print("In ASCII: ",key)
    print("In HEX: ",*key_hex)
    print()
    print("Cipher Text:")
    print("In HEX: ",*encrypted_hex)
    print("In ASCII: ",encrypted_text)
    print()
    print("Deciphered Text:")
    print("In HEX: ",*decrypted_hex)
    print("In ASCII: ",decrypted_text)

    print()
    print("Execution time details")
    print("Key Scheduling: ",key_scheduling_time," seconds")
    print("Encryption time: ",encryption_time," seconds")
    print("Decryption time: ",decryption_time," seconds")
    
if __name__ == "__main__":
    main()
