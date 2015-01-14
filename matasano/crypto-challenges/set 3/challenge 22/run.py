#!/usr/bin/env python

# The matasano crypto challenges - Set 3 Challenge 22 (http://cryptopals.com/sets/3/challenges/22/)
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

from cryptohelper import *

def mt_brute_seed(rg, value, index=0):
	for s in rg:
		mt_init(s)
		for i in range(0, index+1):
			num = mt_next()
		if num == value:
			return s
	return None


def main(argv):
	time.sleep(random.randint(40,1000))
	seed = int(time.time())
	st = mt_init(seed)
	time.sleep(random.randint(40,1000))

	num = mt_next(st)

	cracked_seed = mt_brute_seed(range(int(time.time()), int(time.time())-5000, -1), num)

	if cracked_seed == seed:
		print "WIN"
	else:
		print "LOOSE"


if __name__ == "__main__":
	main(sys.argv)
