#!/usr/bin/env python

# The matasano crypto challenges - Set 2 Challenge 16 (http://cryptopals.com/sets/2/challenges/16/)
#
# Copyright (c) 2015 - Albert Puigsech Galicia (albert@puigsech.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import base64
import sys
import random
import re

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *

key = ''.join([chr(random.randint(0,255)) for i in range(16)])

charset=''.join([chr(i) for i in range(0,256)]) 

data = [
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]


def encrypt_challenge(iv):
	pt = base64.b64decode(data[random.randint(0,len(data)-1)])
	ct = encrypt_block_CBC(pt, 16, iv, key, encrypt_block_AES)
	return iv, ct


def decrypt_challenge(iv, ct):
	try:
		decrypt_block_CBC(ct, 16, iv, key, decrypt_block_AES)
		return True
	except:
		return False
	

# Stupid hack to change one byte in string.
def str_set_chr(s, idx, value):
	s = list(s)
	s[idx] = value
	return ''.join(s)


def challenge_decryptor(iv, ct, charset):
	ct_blocks = block_split(ct)
	guess_pt = ''

	for i in range(-1, len(ct_blocks)-1):
			if i >= 0:
				target = ct_blocks[i]
			else:
				target = iv
			guess_block = "\x00"*16
			for j in range(1,len(target)+1):
				padding = "\x00"*(16-j)+chr(j)*j
				for ch in charset:
					if ch == '\x01' and i == len(ct_blocks)-2:
						continue
					guess_block = str_set_chr(guess_block, 16-j, ch)
					new_target = strxor(target, strxor(guess_block, padding))
					if i >= 0:
						ct_blocks[i] = new_target
					else:
						iv = new_target
					if decrypt_challenge(iv, block_join(ct_blocks[:i+2])) == True:
						break
			guess_pt += guess_block
	return guess_pt


def main(argv):
	iv = ''.join([chr(random.randint(0,255)) for i in range(16)])
	iv,ct = encrypt_challenge(iv)

	print data_unpad_PKCS7(challenge_decryptor(iv,ct, charset))

if __name__ == "__main__":
	main(sys.argv)
