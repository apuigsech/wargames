#!/usr/bin/env python

# The matasano crypto challenges - Set 1 Challenge 6 (http://cryptopals.com/sets/1/challenges/6/)
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

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *


def main(argv):
	with open('6.txt') as f:
		ct = base64.b64decode(f.read())

	keylen = xor_statistical_keylens(ct, 40)[0][0]

	chunks = [ct[i*keylen:(i+1)*keylen] for i in range(len(ct)/keylen)]

	key = ''
	for i in range(keylen):
		pct = ''.join([j[i] for j in chunks])
		key = key + chr(xor_statistical_candidates(pct)[0][0])

	print cryptoxor(ct, key)


if __name__ == "__main__":
   main(sys.argv)
