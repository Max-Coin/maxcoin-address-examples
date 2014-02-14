#!/usr/bin/env python
# MaxCoin address generator
# Input a public key (base64 encoded) and the
# corresponding MaxCoin address will be
# generated
# Luke Mitchell Feb. 2014

import hashlib
import base64
import ctypes
import ctypes.util
import sys

# SHA3 Python module
# https://github.com/bjornedstrom/python-sha3
import sha3

# Hashing algorithms

def hash_keccak(s):
    h1 = sha3.SHA3256()
    h1.update(s)
    return h1.digest()

def hash_sha256(s):
    h1 = hashlib.new('sha256')
    h1.update(s)
    return h1.digest()

def hash_ripemd160(s):
    h1 = hashlib.new('ripemd160')
    h1.update(s)
    return h1.digest()

# Base58 coding functions
# https://github.com/weex/addrgen

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0,(b58_digits[r]))
    return ''.join(l)

def base58_encode_padded(s):
    res = base58_encode(int('0x' + s.encode('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0):
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def base58_decode(s):
    n = 0
    for ch in s:
        n *= 58
        digit = b58_digits.index(ch)
        n += digit
    return n

def base58_decode_padded(s):
    pad = 0
    for c in s:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    h = '%x' % base58_decode(s)
    if len(h) % 2:
        h = '0' + h
    res = h.decode('hex')
    return chr(0) * pad + res

# Address creation functions

def create_address(pubkey):
    # hash public key
    # using RIPEMD160(SHA256(pubkey))
    baby = hash_sha256(pubkey)
    child = hash_ripemd160(baby)

    # add version/network byte (base58 'm')
    version = 110
    teenager = chr(version) + child;

    # hash this using Keccak
    adult = hash_keccak(teenager)

    # take 4 bytes as checksum
    # append these to the end of the string
    checksum = adult[:4]
    pensioner = teenager + checksum;

    # base58 encode the address
    return base58_encode_padded(pensioner)

def validate_address(address):
    k = base58_decode_padded(address)
    v0, data, check0 = k[0], k[1:-4], k[-4:]
    check1 = hash_keccak(v0 + data)[:4]
    if check0 != check1:
        raise BaseException('checksum error')
    if 110 != ord(v0):
        raise BaseException('version mismatch')

# Script entry point

if __name__ == '__main__':
    # Base64 encoded public key
    pubkey_b64 = "BNX5V3mm0Uqu4ZVTB4AQ9IReam0vdsS3va8cuz4A909fVaJC2sqZcsnUL7sOWwz9U1HJehP0UW1tcfKvmfvAJkY="
    pubkey = base64.b64decode(pubkey_b64);

    # MaxCoin address
    address = create_address(pubkey)
    validate_address(address)
    print address


