import os
import numpy as np
from BitVector import *
from tables import *
import math

ROUND_COUNT = {128: 10, 192: 12, 256: 14}
AES_MODULUS = BitVector(bitstring="100011011")


class AES_ECB:
    # key must be 128/192/256
    def __init__(self, key, aes_len):
        self.aes_len = aes_len
        self.key = self.adjustKey(key).encode(
            'utf-8')  # os.urandom(aes_len//8)
        self.all_keys = []

    def adjustKey(self, key):
        # Rather use KDF
        return key[:self.aes_len//8].ljust(self.aes_len//8, '\0')
    
    def string_to_hex_space_separated(self, input_string):
        return " ".join(format(ord(char), "02x") for char in input_string)

    def print_hex_matrix(self, matrix):
        for row in matrix:
            print(' '.join(format(cell, '02x') for cell in row))

    def rot_word(self, list, shift, dir=1):
        shift = shift % len(list)
        return np.concatenate((list[dir * shift:], list[: dir * shift]))

    def gf_multiply(self, bv1, bv2) -> int:
        return self.bitvector_to_int(bv1.gf_multiply_modular(bv2, AES_MODULUS, 8))

    def sub_word(self, list, inv=False):
        sbox = InvSbox if inv else Sbox
        return np.array([sbox[bv] for bv in list])

    def sub_matrix(self, matrix, inv=False):
        for i in range(len(matrix)):
            matrix[i] = self.sub_word(matrix[i], inv)
        return matrix

    def rot_matrix(self, matrix, dir):
        for i in range(len(matrix)):
            matrix[i] = self.rot_word(matrix[i], i, dir)
        return matrix

    def mix_columns(self, matrix, inv=False):
        mixer = InvMixer if inv else Mixer

        rows, cols = matrix.shape
        ret = np.zeros_like(matrix)

        for i in range(rows):
            for j in range(cols):
                for k in range(rows):
                    ret[i][j] ^= self.gf_multiply(
                        mixer[i][k], BitVector(intVal=matrix[k][j]))
        return ret

    def convert_to_ascii(self, matrix):
        return "".join([chr(value) for row in matrix for value in row])
            
    def bitvector_to_int(self, bv):
        return int(bv.get_bitvector_in_hex(), 16)

    def gf_multiply(self, bv1, bv2) -> int:
        return self.bitvector_to_int(bv1.gf_multiply_modular(bv2, AES_MODULUS, 8))

    def func_g(self, word, round_constant):
        word = self.sub_word(self.rot_word(word, 1))
        word[0] ^= round_constant
        return np.array(word)
    
    def pad(self, data, delm=" "):
        while len(data) % (self.aes_len // 8) != 0:
            data += delm
        return data
    
    def unpad(self, data, delm=" "):
        i = len(data) - 1
        while i >= 0 and data[i] == delm:
            i -= 1
        return data[:i+1]
        
    def to_matrix(self, bytes_chunk):
        bytes_matrix = np.zeros((4, 4), dtype=np.uint8)
        k = 0
        for i in range(0, len(bytes_chunk), 4):
            for j in range(4):
                bytes_matrix[i//4,j] = bytes_chunk[k]
                k+=1
                if k == len(bytes_chunk):
                    return bytes_matrix
        return bytes_matrix
    
    def keySchedule(self):
        self.all_keys = np.empty(
            (ROUND_COUNT[self.aes_len] + 1, self.aes_len // 32, 4), dtype=np.uint8)
        key_round_0 = self.to_matrix(self.key)
        self.all_keys[0] = key_round_0
        round_constant = 1
        for round in range(1, ROUND_COUNT[self.aes_len] + 1):
            self.all_keys[round] = np.empty((self.aes_len // 32, 4), dtype=np.uint8)

            self.all_keys[round][0] = self.all_keys[round - 1][0] ^ self.func_g(
                self.all_keys[round - 1][-1], round_constant
            )

            for i in range(1, len(self.all_keys[round - 1])):
                self.all_keys[round][i] = self.all_keys[round][i -
                                                     1] ^ self.all_keys[round - 1][i]

            round_constant = self.gf_multiply(
                BitVector(intVal=round_constant), BitVector(hexstring="02")
            )

        self.all_keys = [np.transpose(key) for key in self.all_keys]
        
    def aes_rounds(self, state, keys, inv=False):
        state = state ^ keys[0]
        for round in range(1, ROUND_COUNT[self.aes_len] + 1):
            if inv:
                state = self.rot_matrix(state, -1)

            state = self.sub_matrix(state, inv)
            if not inv:
                state = self.rot_matrix(state, 1)
            if inv:
                state ^= keys[round]
            if round != ROUND_COUNT[self.aes_len]:
                state = self.mix_columns(state, inv)
            if not inv:
                state ^= keys[round]
        return state
        
    def block_cipher(self, data, keys, decrypt=False):
        crypted_text = ""
        for i in range(0, len(data), self.aes_len // 8):
            block = data[i: i + self.aes_len // 8]
            block = b''.join([bytes([ord(char)]) for char in block])
            block = self.to_matrix(block)
            block = np.transpose(block)  # Column major
            crypted = self.aes_rounds(
                block, keys, decrypt)
            crypted_text += self.convert_to_ascii(np.transpose(crypted))
        return crypted_text
    
    def encrypt(self, plain_text):
        padded_text = self.pad(plain_text)
        return self.block_cipher(padded_text,self.all_keys)

    def decrypt(self, encrypted_text):
        decrypted_text =  self.block_cipher(encrypted_text,self.all_keys[::-1], True)
        return self.unpad(decrypted_text)

def main():    
    key = "Thats my Kung Fu"
    cipher = AES_ECB(key, 128)
    cipher.keySchedule()
    msg = "Two One Nine TwoTwo One Nine Two"
    # msg = input()
    print(cipher.encrypt(msg))
    print(cipher.decrypt(cipher.encrypt(msg)))

# main()

