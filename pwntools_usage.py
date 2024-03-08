#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import *
from Crypto.Hash import SHA256
import base64, hashlib, os, gmpy2, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# HOST = "socket.cryptohack.org"
# PORT = 11112

# r = remote(HOST, PORT)


# def json_recv():
#     line = r.readline()
#     return json.loads(line.decode())

# def json_send(hsh):
#     request = json.dumps(hsh).encode()
#     r.sendline(request)

# print(r.readline())
# print(r.readline())
# print(r.readline())
# print(r.readline())


# request = {
#     "buy": "flag"
# }
# json_send(request)

# response = json_recv()

# print(response)


################################################

# from pwn import * # pip install pwntools
# import json

# r = remote('socket.cryptohack.org', 13377, level = 'debug')

# def json_recv():
#     line = r.recvline()
#     return json.loads(line.decode())

# def json_send(hsh):
#     request = json.dumps(hsh).encode()
#     r.sendline(request)


# received = json_recv()

# print("Received type: ")
# print(received["type"])
# print("Received encoded value: ")
# print(received["encoded"])

# to_send = {
#     "decoded": "100"
# }
# json_send(to_send)

# json_recv()