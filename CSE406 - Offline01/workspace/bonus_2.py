import os
import numpy as np
from BitVector import *
from tables import *
from bonus_1_aes import *
import math
import random
import string

# https://uwillnvrknow.github.io/deCryptMe/pages/programAES.html

def main():
    AES_LEN = 256
    key = "Thats my Kung FuThats my Kung Fu"
    cipher = AES_CBC_EXTENDED(key, AES_LEN)
    cipher.key_expansion()
    msg = "Two One Nine TwoTwo One Nine TwoTwo One Nine Two"
    # msg = input()
    # iv = ''.join(random.choices(string.ascii_letters, k=16))
    iv = "0123456789ABCDEF"
    print("Key", cipher.string_to_hex_space_separated(key))
    print("iv", cipher.string_to_hex_space_separated(iv))
    print("Text", cipher.string_to_hex_space_separated(msg))
    print("Cipher", cipher.string_to_hex_space_separated(cipher.encrypt(msg, iv)[16:]))
    print(cipher.decrypt(cipher.encrypt(msg,iv)))


if __name__ == "__main__":
    main()
