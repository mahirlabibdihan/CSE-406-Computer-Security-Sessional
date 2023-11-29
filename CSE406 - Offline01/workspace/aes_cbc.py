import os
import numpy as np
from BitVector import *
from tables import *
import math

# https://uwillnvrknow.github.io/deCryptMe/pages/programAES.html
ROUND_COUNT = {128: 10, 192: 12, 256: 14}
KEY_COUNT = {128: 44, 192: 52, 256: 60}
AES_MODULUS = BitVector(bitstring="100011011")


class AES_CBC:
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

        
    def block_cipher_cryption(self, plain_text, keys, decrypt):
        block = plain_text.reshape((4, 4))
        block = np.transpose(block)  # Column major
        crypted = self.aes_rounds(block, keys, decrypt)
        return np.transpose(crypted).flatten()

    def block_cipher(self, data, keys, iv, decrypt=False):
        crypted_text = np.empty(0, dtype=np.uint8)

        iv = self.adjustKey(iv)
        last_crypted = np.array([ord(char) for char in iv],  dtype=np.uint8)
        

        last_plain = last_crypted

        for i in range(0, len(data), 16):
            text_chunk = data[i: i + 16]
            bytes_array = np.array([ord(char) for char in text_chunk],  dtype=np.uint8)

            if not decrypt:
                bytes_array = bytes_array ^ last_crypted

            last_crypted = self.block_cipher_cryption(
                bytes_array, keys, decrypt)

            if decrypt:
                last_crypted ^= last_plain

            last_plain = bytes_array
            crypted_text = np.concatenate(
                (crypted_text, last_crypted), dtype=np.uint8)

        return "".join([chr(char) for char in crypted_text])

    def encrypt(self, plain_text, iv):
        padded_text = self.pad(plain_text)
        return self.block_cipher(padded_text, self.all_keys, iv)

    def decrypt(self, encrypted_text, iv):
        decrypted_text = self.block_cipher(
            encrypted_text, self.all_keys[::-1], iv, True)
        return self.unpad(decrypted_text)

def main():    
    key = "Thats my Kung Fu"
    cipher = AES_CBC(key, 128)
    cipher.keySchedule()
    msg = "Two One Nine TwoTwo One Nine Two"
    # msg = input()
    # iv = ("\0"*16).encode('utf-8')
    # iv = os.urandom(16)
    iv = "0123456789ABCDEF"
    print(cipher.encrypt(msg, iv))
    print(cipher.decrypt(cipher.encrypt(msg, iv), iv))

# main()