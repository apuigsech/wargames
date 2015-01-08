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
from cryptohelper import *

key = ''.join([chr(random.randint(0,255)) for i in range(16)])

def encryption_challenge(pt):
	if re.match('.[=;].', pt):
		return None
	pt = pt + ";comment2=%20like%20a%20pound%20of%20bacon"
	iv = ''.join([chr(random.randint(0,255)) for i in range(16)])
	return iv,encrypt_block_CBC(pt, 16, iv, key, encrypt_block_AES)
	

def decryption_challenge(ct, iv):
	pt = decrypt_block_CBC(ct, 16, iv, key, decrypt_block_AES)
	if ";admin=true;" in pt:
		return True
	else:
		return False


def tamper_data(ct, fakedata, idx):
	ct_blocks = block_split(ct, 16)
	ct_blocks[idx-1] = strxor(ct_blocks[idx-1], strxor("A"*16, fakedata))
	return block_join(ct_blocks)


def main(argv):
	iv,ct = encryption_challenge("A"*64)

	new_ct = tamper_data(ct, ";admin=true;AAAA", 2)

	if decryption_challenge(new_ct, iv) == True:
		print "WIN!"
	else:
		print "LOSE!"


if __name__ == "__main__":
	main(sys.argv)