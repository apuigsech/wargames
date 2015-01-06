#!/usr/bin/env python

# The matasano crypto challenges - Set 1 Challenge 8 (http://cryptopals.com/sets/1/challenges/8/)
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

# BEGIN: Functions from cryptohelper
def unique_blocks_ratio(text, blocklen, numblocks=None):
	if (numblocks == None):
		numblocks = len(text)/blocklen

	unique_chunks = set([text[i*blocklen:(i+1)*blocklen] for i in range(numblocks)])

	return float(len(unique_chunks))/numblocks
# END: Functions from cryptohelper


def main(argv):
	with open('8.txt') as f:
		ct_samples = [line.rstrip().decode('hex') for line in f]

	print sorted([[ct, unique_blocks_ratio(ct, 16)] for ct in ct_samples], key=lambda x: x[1])[0][0].encode('hex')


if __name__ == "__main__":
   main(sys.argv)
