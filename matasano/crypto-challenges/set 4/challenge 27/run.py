#!/usr/bin/env python

# The matasano crypto challenges - Set 4 Challenge 27 (http://cryptopals.com/sets/3/challenges/27/)
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


import sys
import random

from cryptohelper import *


key = ''.join([chr(random.randint(0,255)) for i in range(16)])
iv = key

def encryption_challenge(pt):
	return encrypt_block_CBC(pt, 16, iv, key, encrypt_block_AES)
	

def decryption_challenge(ct):
	return decrypt_block_CBC(ct, 16, iv, key, decrypt_block_AES)


def main(argv):
	pt = "\x00" * 16*3
	ct = encryption_challenge(pt)

	ct = "\x00"*32 + ct[32:]
	pt = decryption_challenge(ct)

	ct_blocks = block_split(ct)
	pt_blocks = block_split(pt)

	guess_iv = strxor(pt_blocks[1], pt_blocks[0])
	guess_key = guess_iv

	if guess_key == key:
		print "WIN"
	else:
		print "LOSE"


if __name__ == "__main__":
	main(sys.argv)
