# -*- coding=utf-8 -*-
# Zhaijiahui
# https://github.com/zhaijiahui

import os,sys

base = [str(x) for x in range(10)] + [ chr(x) for x in range(ord('A'),ord('A')+6)]

#十进制0~255转化为二进制,补0到8位
def dec2bin80(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0: break
        num,rem = divmod(num, 2)
        mid.append(base[rem])

    result = ''.join([str(x) for x in mid[::-1]])
    length = len(result)
    if length < 8:
        result = '0' * (8 - length) + result
    return result


#十进制0~255转化为二进制,补0到32位
def dec2bin320(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0: break
        num,rem = divmod(num, 2)
        mid.append(base[rem])

    result = ''.join([str(x) for x in mid[::-1]])
    length = len(result)
    if length < 32:
        result = '0' * (32 - length) + result
    return result


#十进制0~255转化为二进制，不补零
def dec2bin(string_num):
    num = int(string_num)
    mid = []
    while True:
        if num == 0: break
        num,rem = divmod(num, 2)
        mid.append(base[rem])

    return ''.join([str(x) for x in mid[::-1]])


#二进制转换为十进制
def bin2dec(string_num):
    return str(int(string_num, 2))

#ip列表生成
def iplist(string_startip,string_endip):

    #分割IP，然后将其转化为8位的二进制代码
    start = string_startip.split('.')
    start_a = dec2bin80(start[0])
    start_b = dec2bin80(start[1])
    start_c = dec2bin80(start[2])
    start_d = dec2bin80(start[3])
    start_bin = start_a + start_b + start_c + start_d
    #将二进制代码转化为十进制
    start_dec = bin2dec(start_bin)

    end = string_endip.split('.')
    end_a = dec2bin80(end[0])
    end_b = dec2bin80(end[1])
    end_c = dec2bin80(end[2])
    end_d = dec2bin80(end[3])
    end_bin = end_a + end_b + end_c + end_d
    #将二进制代码转化为十进制
    end_dec = bin2dec(end_bin)

    #十进制相减，获取两个IP之间有多少个IP
    count = int(end_dec) - int(start_dec)

    ip_list = []
    #生成IP列表
    for i in range(0,count + 1):
        #将十进制IP加一，再转化为二进制（32位补齐）
        plusone_dec = int(start_dec) + i
        plusone_dec = str(plusone_dec)
        address_bin = dec2bin320(plusone_dec)
        #分割IP，转化为十进制
        address_a = bin2dec(address_bin[0:8])
        address_b = bin2dec(address_bin[8:16])
        address_c = bin2dec(address_bin[16:24])
        address_d = bin2dec(address_bin[24:32])
        address = address_a + '.'+ address_b +'.'+ address_c +'.'+ address_d
        ip_list.append(address)
    return ip_list