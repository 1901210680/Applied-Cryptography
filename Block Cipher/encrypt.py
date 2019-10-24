#!/usr/bin/env python
# -*- coding:utf-8 -*-
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
from PIL import Image


class Encrypt:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, raw_file, enc_file1, enc_file2):
        image = Image.open(raw_file)
        image_rgba = image.convert('RGBA')
        width, height = image_rgba.size
        ecb_image = Image.frombytes('RGBA', (width, height), self.ecb(image_rgba.tobytes())).convert('RGB')
        cbc_image = Image.frombytes('RGBA', (width, height), self.cbc(image_rgba.tobytes())).convert('RGB')
        ecb_image.save(enc_file1)
        cbc_image.save(enc_file2)

    def ecb(self, value):
        key = b'1901210680WCYwcy'
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(self.key, SM4_ENCRYPT)
        ecb_value = crypt_sm4.crypt_ecb(value)  #  bytes类型
        return ecb_value

    def cbc(self, value):
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(self.key, SM4_ENCRYPT)
        cbc_value = crypt_sm4.crypt_cbc(self.iv, value)
        return cbc_value


raw_file = r'pkulogo.jpg'
ebc_file = r'ebc_logo.jpg'
cbc_file = r'cbc_logo.jpg'
key = b'1901210680WCYwcy'
IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
e = Encrypt(key, IV)
e.encrypt(raw_file, ebc_file, cbc_file)
