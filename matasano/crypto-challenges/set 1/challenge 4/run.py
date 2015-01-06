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

# BEGIN: Functions from cryptohelper
def strxor(a, b):
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

freq_eng = {
	'a':8.167, 'b':1.492, 'c':2.782,'d':4.253,'e':12.702,'f':2.228,'g':2.015,'h':6.094,
	'i':6.966,'j':0.153,'k':0.772,'l':4.025,'m':2.406,'n':6.749,'o':7.507,'p':1.929,
	'q':0.095,'r':5.987,'s':6.327,'t':9.056,'u':2.758,'v':0.978,'w':2.360,'x':0.150,
	'y':1.974,'z':0.074
}


def text_frequency_score(text, freq, average=True):
	score = 0.0
	for ch in text:
		if freq.has_key(ch):
			score += 10 + freq[ch]
	if average == True:
		score = score/len(text)
	return score


def xor_statistical_candidates(ct, freq=freq_eng):
	candidates = []
	for key in range(0,255):
		pt = strxor(ct,chr(key)*len(ct))
		candidates.append([key, pt, text_frequency_score(pt, freq)])
	return sorted(candidates, key=lambda x: x[2], reverse=True)
# END: Functions from cryptohelper


def main(argv):
	with open('4.txt') as f:
		ct_samples = [line.rstrip().decode('hex') for line in f]

	pt_candidates = []
	for ct in ct_samples:
		pt_candidates += xor_statistical_candidates(ct)

	pt_candidates = sorted(pt_candidates, key=lambda x: x[2], reverse=True)
	print pt_candidates[0][1]
	

if __name__ == "__main__":
   main(sys.argv)
