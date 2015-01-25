#!/usr/bin/env python

# The matasano crypto challenges - Set 4 Challenge 29 (http://cryptopals.com/sets/3/challenges/29/)
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

from cryptohelper import *


key = ''.join([chr(random.randint(0,255)) for i in range(16)])


def sha1_MAC(m, k):
	return sha1(k + m)


def challenge_MAC_calc(m):
	return m, sha1_MAC(m, key)


def challenge_MAC_check(m, hash):
	h = sha1_MAC(m, key)
	if h == hash:
		return True
	else:
		return False


def guess_keylen():
	# TODO: Find way to get it.
	return 16


def tamper_data(data, hash, new_data):
	keylen = guess_keylen()

	m = message_pad(data, len(data)+keylen, "B") + new_data

	s = struct.unpack(">IIIII", hash)
	new_data = message_pad(new_data, len(m)+keylen, "B")
	h = sha1(new_data, s, False)

	return m, h


def main(argv):
	message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	new_message = ";admin=true"

	m_orig,h_orig = challenge_MAC_calc(message)
	m_tamper,h_tamper = tamper_data(m_orig, h_orig, new_message)

	if challenge_MAC_check(m_tamper, h_tamper) == True:
		print "WIN"
	else:
		print "LOSE"


if __name__ == "__main__":
	main(sys.argv)
