#!/usr/bin/env python

# The matasano crypto challenges - Set 3 Challenge 24a (http://cryptopals.com/sets/3/challenges/24/)
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
import time

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *


def challenge_encrypt(kpt):
	pt = ''.join([chr(random.randint(0,255)) for i in range(random.randint(0, 1000))]) + kpt
	k = random.getrandbits(16)
	return encrypt_mt(pt, k)

def main(argv):
	kpt = "A" * 14
	ct = challenge_encrypt(kpt)
	
	key = None
	for i in range(0xffff):
		bfct = encrypt_mt("A"*len(ct), i)

		if ct[-14:] == bfct[-14:]:
			key = i
			break

	if key != None:
		print "Found Key:", key
	else:
		print "Key not found!"


if __name__ == "__main__":
	main(sys.argv)
