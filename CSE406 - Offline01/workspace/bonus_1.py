import os
import numpy as np
from BitVector import *
from tables import *
from aes_cbc import *
import math

# https://uwillnvrknow.github.io/deCryptMe/pages/programAES.html
ROUND_COUNT = {128: 10, 192: 12, 256: 14}
KEY_COUNT = {128: 44, 192: 52, 256: 60}
AES_MODULUS = BitVector(bitstring="100011011")


class GENERIC_AES_CBC(AES_CBC):
    def pad(self, data):
        width = self.aes_len // 8
        if(len(data) % (width) == 0):
            for i in range(width):
                data += chr(0)
        
        else:
            need = (width) - len(data) % (width)
            while len(data) % (width) != 0:
                data += chr(need)
        return data
    
    def unpad(self, data):
        width = self.aes_len // 8
        flag = True
        for i in range (len(data)-width,len(data)):
            if(ord(data[i])!=0):
                flag = False
                break
        if flag:
            return ''.join(data[i] for i in range (len(data)-width))
        else:
            return ''.join(data[i] for i in range (len(data)-ord(data[-1])))


# cipher = AES_CBC(128)
# cipher.keySchedule()

# msg="Never Gonna give you up"
# msg = input()
# iv = os.urandom(16)
# # print(len(cipher.encrypt(msg, iv)))
# print(cipher.decrypt(cipher.encrypt(msg, iv), iv))

