#!/usr/bin/env python

# The matasano crypto challenges - Set 3 Challenge 24b (http://cryptopals.com/sets/3/challenges/24/)
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
import base64
import random
import time

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *


def challenge_token():
	seed = int(time.time())
	st = mt_init(seed)
	for i in range(random.randint(10,500)):
		mt_next(st)
	return base64.b64encode(struct.pack("I", mt_next(st)))


def seed_from_token(tk, surface=100, deepth=1000):
	n = struct.unpack("I", base64.b64decode(tk))[0]
	now = int(time.time())
	for i in range(-surface, surface):
		st = mt_init(now + i)
		for j in range(deepth):
			if  mt_next(st) == n:
				return now+i
	return None


def main(argv):
	tk = challenge_token()
	time.sleep(random.randint(10,60))
	seed = seed_from_token(tk)

	if seed != None:
		print "Found Seed:", seed
	else:
		print "Seed not found!"


if __name__ == "__main__":
	main(sys.argv)
