#!/usr/bin/env python

# The matasano crypto challenges - Set 1 Challenge 4 (http://cryptopals.com/sets/1/challenges/4/)
#
# Copyright (c) 2014 - Albert Puigsech Galicia (albert@puigsech.com)
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

def strxor(a, b):
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def calculate_statistical_score(plaintext):
	score = 0
	eng_freq="ETAOINSHRDLCUMWFGYPBVKJXQZ"
	for ch in plaintext:
		try:
			score += eng_freq[::-1].index(ch)
		except:
			score += 0
	return (score/len(plaintext))

def generate_xor_candidates(ct):
	candidates = []
	for key in range(0,255):
		pt = strxor(ct,chr(key)*len(ct))
		sc = calculate_statistical_score(pt)
		candidates.append([sc, pt])
	return sorted(candidates, key=lambda x: x[0], reverse=True)


def main(argv):
	with open('4.txt') as f:
		ct_samples = [line.rstrip().decode('hex') for line in f]

	pt_candidates = []
	for ct in ct_samples:
		pt_candidates += generate_xor_candidates(ct)

	pt_candidates = sorted(pt_candidates, key=lambda x: x[0], reverse=True)
	print pt_candidates[0][1]
	

if __name__ == "__main__":
   main(sys.argv)
