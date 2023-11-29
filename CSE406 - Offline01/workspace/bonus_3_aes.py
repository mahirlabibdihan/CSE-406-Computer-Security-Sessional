import os
import numpy as np
from BitVector import *
from tables import *
import math
import random
from concurrent.futures import ProcessPoolExecutor
from Crypto.Util import Counter
import secrets
# https://uwillnvrknow.github.io/deCryptMe/pages/programAES.html
ROUND_COUNT = {128: 10, 192: 12, 256: 14}
KEY_COUNT = {128: 44, 192: 52, 256: 60}
AES_MODULUS = BitVector(bitstring="100011011")


class AES_CTR:
    # key must be 128/192/256
    def __init__(self, key, nonce, aes_len):
        self.aes_len = aes_len
        self.nonce = nonce
        self.counter = 0
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

    def pad(self, data):
        while len(data) % 16 != 0:
            data += " "
        return data
    
    def unpad(self, data):
        i = len(data) - 1
        while i >= 0 and data[i].isspace():
            i -= 1
        return data[:i+1]

    def to_matrix(self, bytes_chunk, n_rows, n_cols):
        bytes_matrix = np.zeros((n_rows, n_cols), dtype=np.uint8)
        k = 0
        for i in range(n_rows):
            for j in range(n_cols):
                bytes_matrix[i, j] = bytes_chunk[k]
                k += 1
                if k == len(bytes_chunk):
                    return bytes_matrix
        return bytes_matrix
    
    def keySchedule(self):
        n = self.aes_len // 32
        self.all_rounds = np.empty(
            (ROUND_COUNT[self.aes_len] + 1, n, 4), dtype=np.uint8)
        key_round_0 = self.to_matrix(self.key, n, 4)
        self.all_rounds[0] = key_round_0
        round_constant = 1
        for round in range(1, ROUND_COUNT[self.aes_len] + 1):
            self.all_rounds[round] = np.empty((n, 4), dtype=np.uint8)

            self.all_rounds[round][0] = self.all_rounds[round - 1][0] ^ self.func_g(
                self.all_rounds[round - 1][-1], round_constant
            )

            for i in range(1, len(self.all_rounds[round - 1])):
                self.all_rounds[round][i] = self.all_rounds[round][i -
                                                                   1] ^ self.all_rounds[round - 1][i]

            round_constant = self.gf_multiply(
                BitVector(intVal=round_constant), BitVector(hexstring="02")
            )

        original_shape = self.all_rounds.shape
        
        self.all_keys = np.zeros((original_shape[0],4,4), dtype=np.uint8)
        i = 0
        j = 0
        for word in self.all_rounds.reshape(original_shape[0]*original_shape[1], 4):
            self.all_keys[i][j] = word
            j += 1
            if (j == 4):
                i += 1
                j = 0
            if (i == ROUND_COUNT[self.aes_len] + 1):
                break
            
        self.all_keys = [np.transpose(key) for key in self.all_keys]
        # self.all_keys = [np.transpose(key) for key in self.all_rounds]

    def binary_to_array(self, binary_string):
        return np.array([int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8)])

    def block_cipher_cryption(self, plain_text, keys, counter):
        
        random_text = int(self.nonce) + int(counter)
        random_text = bin(random_text)[2:]
        random_text = self.binary_to_array(random_text)
        
        block = random_text.reshape((4, 4))
        block = np.transpose(block)  # Column major
        crypted = self.aes_rounds(block, keys)
        crypted = np.transpose(crypted).flatten()

        return crypted[:len(plain_text)] ^ plain_text

    def block_cipher(self, data, keys):
        with ProcessPoolExecutor() as executor:
            blocks = [np.array([ord(char) for char in data[i:i + 16]],  dtype=np.uint8) for i in range(0, len(data), 16)]

            encrypted_blocks = list(executor.map(self.block_cipher_cryption, blocks, [keys] * len(blocks),range(len(blocks))))

            ciphertext = ""
            for crypted_block in encrypted_blocks:
                for char in crypted_block:
                    ciphertext += chr(char)
        self.counter += len(blocks)
        return ciphertext

    def encrypt(self, plain_text):
        padded_text = self.pad(plain_text)
        return self.block_cipher(padded_text, self.all_keys)
    
    def decrypt(self, encrypted_text):
        return self.block_cipher(encrypted_text, self.all_keys)

def main():    
    key = "Thats my Kung Fu"
    cipher = AES_CTR(key, secrets.randbits(128), 128)
    cipher.keySchedule()
    msg = "Two One Nine TwoTwo One Nine Two"
    # msg = input()
    enc = cipher.encrypt(msg)
    cipher.counter -= math.ceil(len(msg)/16)
    # print(cipher.encrypt(enc))

# main()