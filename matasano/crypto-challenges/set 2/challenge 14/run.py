#!/usr/bin/env python

# The matasano crypto challenges - Set 2 Challenge 14 (http://cryptopals.com/sets/2/challenges/14/)
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

import base64
import sys
import random
from cryptohelper import *

key = ''.join([chr(random.randint(0,255)) for i in range(16)])
unknown_pt_pre = ''.join([chr(random.randint(0,255)) for i in range(random.randint(5,32))])
unknown_pt_post = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

charset=''.join([chr(i) for i in range(256)])


def oracle_decryption(challenge):
	blocksize = oracle_blocksize(challenge)

	if oracle_isECB(challenge, blocksize) == False:
		return None

	prefix_len = oracle_ECB_prefix_len(challenge, blocksize)
	
	return oracle_ECB_decrypt(challenge, len(challenge('')), blocksize, charset, prefix_len)



def encryption_challenge(data):
	pt = unknown_pt_pre + data + unknown_pt_post
	return encrypt_block_ECB(pt, 16, key, encrypt_block_AES)


def main(argv):
	print oracle_decryption(encryption_challenge)


if __name__ == "__main__":
	main(sys.argv)