#!/usr/bin/env python

# The matasano crypto challenges - Set 3 Challenge 23 (http://cryptopals.com/sets/3/challenges/23/)
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
import time

from cryptohelper import *


def untemper(y):
	y = y ^ (y>>18)
	a = y ^ (y<<15 & 4022730752)
	y = y ^ (a<<15 & 4022730752)
	a = y ^ (y<<7 & 2636928640)
	b = y ^ (a<<7 & 2636928640)
	c = y ^ (b<<7 & 2636928640)
	d = y ^ (c<<7 & 2636928640)
	y = y ^ (d<<7 & 2636928640)
	a = y ^ (y>>11)
	y = y ^ (a>>11)
	return y


def main(argv):
	st = mt_init(int(time.time()))

	matrix_guess = []

	for i in range(624):
		n = untemper(mt_next(st))
		matrix_guess.append(n)

	st_guess = [0, matrix_guess]

	for i in range(10):
		if mt_next(st) != mt_next(st_guess):
			i = i-1
			break

	if i == 9:
			print "WIN"
	else:
			print "LOSE"


if __name__ == "__main__":
	main(sys.argv)
