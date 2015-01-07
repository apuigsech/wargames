#!/usr/bin/env python

# The matasano crypto challenges - Set 2 Challenge 12 (http://cryptopals.com/sets/2/challenges/12/)
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
from itertools import combinations
from cryptohelper import *

key = ''.join([chr(random.randint(0,255)) for i in range(16)])

mode_ecb = 0
mode_cbc = 1

#charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 ,.'-\n"
charset=''.join([chr(i) for i in range(256)])

def encryption_oracle(known_pt, unknown_pt):
	pt = known_pt + unknown_pt
	return encrypt_block_ECB(pt, 16, key, encrypt_block_AES)
	

def decryption_oracle(unknown_pt):
	init_len = len(encryption_oracle("", unknown_pt))

	for i in range(50):
		known_pt = "A"*i
		blocksize = len(encryption_oracle(known_pt, unknown_pt)) - init_len
		if blocksize != 0:
			break
		
	numblocks = init_len/blocksize

	ct = encryption_oracle("A"*1024, unknown_pt)
	if unique_blocks_ratio(ct, 16) < 1:
		mode = mode_ecb
	else:
		mode = mode_cbc

	guess_pt = ""
	guess_string = "A"*blocksize
	for i in range(numblocks):
		guess_block=""
		for j in range(1,blocksize+1):
			known_pt = ""
			for ch in charset:
				known_pt = known_pt + guess_string[j:] + guess_block + ch
			index_ct = block_split(encryption_oracle(known_pt, unknown_pt), blocksize)
			b = block_split(encryption_oracle(guess_string[j:], unknown_pt), blocksize)
			if b[i] in index_ct:
				z = index_ct.index(b[i])
				guess_block = guess_block + charset[z]
		guess_string = guess_block
		guess_pt = guess_pt + guess_block

	return blocksize,mode,guess_pt


def main(argv):
	str="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	blocksize,mode,guess_pt = decryption_oracle(base64.b64decode(str))
	print guess_pt


if __name__ == "__main__":
   main(sys.argv)

