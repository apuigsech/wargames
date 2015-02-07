#!/usr/bin/env python

# The matasano crypto challenges - Set 2 Challenge 11 (http://cryptopals.com/sets/2/challenges/11/)
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

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *


mode_ecb = 0
mode_cbc = 1


def encryption_oracle(pt):
	key = ''.join([chr(random.randint(0,255)) for i in range(16)])
	mode = random.randint(0,1)

	count_before = random.randint(5,10)
	count_after = random.randint(5,10)

	pt = ''.join([chr(random.randint(0,255)) for i in range(count_before)]) + pt + ''.join([chr(random.randint(0,255)) for i in range(count_after)])

	if mode == mode_ecb:
		ct = encrypt_block_ECB(pt, 16, key, encrypt_block_AES)
	elif mode == mode_cbc:
		iv = ''.join([chr(random.randint(0,255)) for i in range(16)])
		ct = encrypt_block_CBC(pt, 16, iv, key, encrypt_block_AES)
	return ct,mode

def detection_oracle(ct):
	if unique_blocks_ratio(ct, 16) < 1:
		return mode_ecb
	else:
		return mode_cbc

def main(argv):
	for i in range(50):
		pt = "A"*1024
		ct, mode = encryption_oracle(pt)
		guess_mode = detection_oracle(ct)

		if (guess_mode == mode):
			print "Guess OK"
		else:
			print "Guess FAIL"




if __name__ == "__main__":
   main(sys.argv)

