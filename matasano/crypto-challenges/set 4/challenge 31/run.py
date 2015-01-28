#!/usr/bin/env python

# The matasano crypto challenges - Set 4 Challenge 31 (http://cryptopals.com/sets/4/challenges/31/)
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
import struct
import time

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *


key = ''.join([chr(random.randint(0,255)) for i in range(64)])


def insecure_equal(s1, s2):
	if len(s1) != len(s2):
		return False

	for i in range(len(s1)):
		if s1[i] != s2[i]:
			return False
		time.sleep(0.25)

	return True


def challenge_read_file(filename, digest):
	with open(filename) as f:
		m = f.read()

	d = HMAC(m, key, 64, sha1)

	if insecure_equal(d, digest):
		return m
	else:
		return None


def bruteforce_digest(filename):
	current_diggest = ["\x00"]*20
	current_time_range = 0.25
	for i in range(20):
		for byte in range(256):
			current_diggest[i] = chr(byte)
			t1 = time.time()
			content = challenge_read_file(filename, ''.join(current_diggest))
			if content != None:
				return content
			t2 = time.time()
			if t2-t1 > current_time_range:
				current_time_range += 0.25
				break


def main(argv):
	print bruteforce_digest("/etc/passwd")


if __name__ == "__main__":
	main(sys.argv)
