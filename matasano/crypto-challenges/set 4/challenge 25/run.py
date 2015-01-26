#!/usr/bin/env python

# The matasano crypto challenges - Set 4 Challenge 25 (http://cryptopals.com/sets/4/challenges/25/)
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
import base64

from cryptohelper import *


key = ''.join([chr(random.randint(0,255)) for i in range(16)])


# Not in elegant way, I know.
def edit_block(ct, newtext, key, seek, blocklen=16):
	pt = decrypt_block_CTR(ct, blocklen, "\x00"*16, key, encrypt_block_AES, True)
	pt_new = pt[0:seek] + newtext + pt[seek+len(newtext):];
	return encrypt_block_CTR(pt_new, blocklen, "\x00"*16, key, encrypt_block_AES, True)


def challenge_edit_block(ct, newtext, seek):
	return edit_block(ct, newtext, key,seek)


def main(argv):
	with open('25.txt') as f:
		ct = encrypt_block_CTR(decrypt_block_ECB(base64.b64decode(f.read()), 16, 'YELLOW SUBMARINE', decrypt_block_AES), 16, "\x00"*16, key, encrypt_block_AES, True)

	new_pt = "\x00"*len(ct)
	ks = challenge_edit_block(ct, new_pt, 0)
	pt = strxor(ct, ks)

	print pt


if __name__ == "__main__":
	main(sys.argv)
