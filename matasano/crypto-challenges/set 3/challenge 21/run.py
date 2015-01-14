#!/usr/bin/env python

# The matasano crypto challenges - Set 3 Challenge 21 (http://cryptopals.com/sets/3/challenges/21/)
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


mt_matrix = []
mt_idx = 0


def mt_init(seed):
	global mt_idx

	mt_idx = 0
	mt_matrix.append(seed & 0xffffffff)
	for i in range(1,624):
		mt_matrix.append(((1812433253 * (mt_matrix[i-1] ^ (mt_matrix[i-1]>>30)) + i)) & 0xffffffff)



def mt_next():
	global mt_idx
	if mt_idx == 0:
		mt_gen_numbers()

	y = mt_matrix[mt_idx]
	y = y ^ (y>>11)
	y = y ^ (y<<7 & 2636928640)
	y = y ^ (y<<15 & 4022730752)
	y = y ^ (y>>18)

	mt_idx = (mt_idx + 1)%624

	return y


def mt_gen_numbers():
	for i in range(624):
		y = mt_matrix[i] = (mt_matrix[i] & 0x80000000) + (mt_matrix[(i+1)%264] & 0x7fffffff)
		mt_matrix[i] = mt_matrix[(i+397)%624] ^ (y>>1)
		if (y%2) != 0:
			mt_matrix[i] = mt_matrix[i] ^ 2567483615


def main(argv):
	mt_init(0)

	# Samples
	for i in range(20):
		print mt_next()


if __name__ == "__main__":
	main(sys.argv)