import numpy as np
from BitVector import *
from tables import *
from performance import *

ROUND_COUNT = {128: 10, 192: 12, 256: 14}
KEY_COUNT = {128: 44, 192: 52, 256: 60}
AES_MODULUS = BitVector(bitstring="100011011") # 11B


class AES_CBC:
    # key must be 128/192/256
    def __init__(self, key, aes_len):
        self.aes_len = aes_len
        self.key = self.adjust_key(key, aes_len//8)
        self.key = [ord(char) for char in self.key]
        self.all_keys = []

    def adjust_key(self, key, len):
        # Rather use KDF
        return key[:len].ljust(len, '\0')

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
        return np.array([sbox[bv] for bv in list], dtype=np.uint8)

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
                # print(state)
                # print(keys[round])
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
        return np.array(word, dtype=np.uint8)

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
    
    # https://en.wikipedia.org/wiki/AES_key_schedule
    def key_expansion(self):
        expanded_key = [int(c) for c in self.key]
        expanded_key = [np.array(expanded_key[i:i+4], dtype=np.uint8)
                        for i in range(0, len(expanded_key), 4)]

        N = self.aes_len // 32
        round_num = self.aes_len // 32
        round_constant = 1
        while round_num < KEY_COUNT[self.aes_len]:
            from_N_rounds_ago = expanded_key[round_num-N]
            # print(from_N_rounds_ago)
            prev_round = expanded_key[round_num-1]
            if round_num % N == 0:
                word = self.func_g(prev_round, round_constant)
                word = from_N_rounds_ago ^ word
                  
                round_constant = self.gf_multiply(
                BitVector(intVal=round_constant), BitVector(hexstring="02")
            )
            elif round_num>=N and N>6 and round_num % N == 4:
                word = from_N_rounds_ago ^ self.sub_word(prev_round)
            else:
                word = from_N_rounds_ago ^ prev_round
            expanded_key.append(word)
            round_num += 1

        keys = [expanded_key[loop:loop+4]
                for loop in range(0, len(expanded_key), 4)]
        # print(keys)
        self.all_keys = [np.transpose(key) for key in keys]


    def block_cipher_cryption(self, plain_text, keys, decrypt):
        block = plain_text.reshape((4, 4))
        block = np.transpose(block)  # Column major
        crypted = self.aes_rounds(block, keys, decrypt)
        return np.transpose(crypted).flatten()

    def block_cipher(self, data, keys, iv, decrypt=False):
        crypted_text = np.empty(0, dtype=np.uint8)

        iv = self.adjust_key(iv, 16)
        last_crypted = np.array([ord(char) for char in iv],  dtype=np.uint8)

        last_plain = last_crypted

        for i in range(0, len(data), 16):
            text_chunk = data[i: i + 16]
            bytes_array = np.array([ord(char)
                                   for char in text_chunk],  dtype=np.uint8)

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
        return iv + self.block_cipher(padded_text, self.all_keys, iv)

    def decrypt(self, encrypted_text):
        decrypted_text = self.block_cipher(
            encrypted_text[16:], self.all_keys[::-1], encrypted_text[:16], True)
        return self.unpad(decrypted_text)


def main():
    key = "Thats my Kung Fu"
    cipher = AES_CBC(key, 128)
    cipher.key_expansion()

    msg = "Two One Nine TwoTwo One Nine Two"
    # msg = input()
    # iv = ("\0"*16).encode('utf-8')
    iv = "0123456789ABCDEF"
    
    print(cipher.encrypt(msg, iv)[16:])
    print(cipher.decrypt(cipher.encrypt(msg, iv)))


if __name__ == "__main__":
    main()
