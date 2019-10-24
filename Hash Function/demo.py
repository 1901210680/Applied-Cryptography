#!/usr/bin/env python
# -*- coding:utf-8 -*-
import sm3
import func


secret = 'secret'
data = input('输入用户名：')
append = input('输入密码：')
'''
计算在secret作用下给数据data加密的结果，该结果可作为IV供attacker使用

'''
init_input = func.bytes_to_list((secret+data).encode('utf-8'))
sm3_init = sm3.SM3()
init_hash_val = sm3_init.sm3_hash(init_input)

'''
server端的正常加密过程：输入secret+data+padding后计算其hash值H(secret||data||padding||append)

'''
sm3_1 = sm3.SM3()
raw_input = func.bytes_to_list((secret+data).encode('utf-8'))
#padding
byte_length = len(raw_input)
bit_length = byte_length * 8
byte_end = 56
while byte_length > byte_end:
    byte_end += 64
for i in range(byte_length, byte_end):
    if i == byte_length:
        raw_input.append(0x80)
    else:
        raw_input.append(0)
bit_length_str = [bit_length % 0x100]
for i in range(7):
    bit_length = int(bit_length / 0x100)
    bit_length_str.append(bit_length % 0x100)
for i in range(8):
    raw_input.append(bit_length_str[7 - i])

append_input = func.bytes_to_list(append.encode('utf-8'))
extension_input = raw_input + func.bytes_to_list(append_input)
server_hash_val = sm3_1.sm3_hash(extension_input)
print('The hash value of server is: ', server_hash_val)

'''
attacker端的攻击过程：在已知secret||data的长度以及hash值的前提下，将该hash值赋值给sm3的初始向量，
便可计算hash值H(H(secret||padding)||append)=H'(append)进行长度扩展攻击
'''
sm3_2 = sm3.SM3()
fake_init_length = 56
while len(secret+data) > fake_init_length:
    fake_init_length += 64
sm3_2.initmsg = 'A' * (fake_init_length+8)
sm3_2.IV = [int(init_hash_val[0:8], 16), int(init_hash_val[8:16], 16),
            int(init_hash_val[16:24], 16), int(init_hash_val[24:32], 16),
            int(init_hash_val[32:40], 16), int(init_hash_val[40:48], 16),
            int(init_hash_val[48:56], 16), int(init_hash_val[56:64], 16)]
attack_hash_val = sm3_2.sm3_hash(append_input)
print('The hash value of attacker is:', attack_hash_val)

'''
判断Extension Length Attack是否成功
'''
print('Login Success') if server_hash_val == attack_hash_val else print('Fatal Error!')