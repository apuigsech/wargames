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


def strxor(a, b):
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])


def cryptoxor(input, key):
	ks = key*((len(input)/len(key))+1)
	return strxor(input, ks)


def hamming_distance(s1, s2):
	dist = 0
	if len(s1) == len(s2):
		for i in range(0, len(s1)):
			if s1[i] != s2[i]:
				dist = dist+1
	return dist


def bit_hamming_distance(s1, s2):
	b1 = ''.join(format(ord(x), '08b') for x in s1)
	b2 = ''.join(format(ord(x), '08b') for x in s2)
	return hamming_distance(b1,b2)


def calculate_statistical_score(plaintext):
	score = 0
	eng_freq="etaoinshrdlcumwfgypbvkjxqz"
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
		candidates.append([sc, pt, key])
	return sorted(candidates, key=lambda x: x[0], reverse=True)


def get_keylen_score(ct, keylen, samples):
	chunks = [ct[i*keylen:(i+1)*keylen] for i in range(samples)]
	global_distance = 0
	for c1 in chunks:
		for c2 in chunks[chunks.index(c1)+1:]:
			global_distance = global_distance + float(bit_hamming_distance(c1, c2))/keylen
	return global_distance/(samples*(samples-1)/2)


def get_statistical_keylen(ct, maxlen):
	scores = []
	for keylen in range(1, maxlen):
		score = get_keylen_score(ct, keylen, 7)
		scores.append([keylen,score])
	return sorted(scores, key=lambda x: x[1])


def main(argv):
	with open('6.txt') as f:
		ct = base64.b64decode(f.read())

	keylen = get_statistical_keylen(ct, 40)[0][0]
	print "Keylen:", keylen

	chunks = [ct[i*keylen:(i+1)*keylen] for i in range(len(ct)/keylen)]

	key = ''
	for i in range(keylen):
		pct = ''.join([j[i] for j in chunks])
		key = key + chr(generate_xor_candidates(pct)[0][2])
	print "Key:", key

	print cryptoxor(ct, key)


if __name__ == "__main__":
   main(sys.argv)
