#!/usr/bin/env python

# The matasano crypto challenges - Set 2 Challenge 15 (http://cryptopals.com/sets/2/challenges/15/)
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
import random

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *


pt_list = [
	"ICE ICE BABY\x04\x04\x04\x04",
	"ICE ICE BABY\x05\x05\x05\x05",
	"ICE ICE BABY\x01\x02\x03\x04"
]


def main(argv):
	for pt in pt_list:
		print "UNPAD:", pt.encode('hex')
		try:
			print data_unpad_PKCS7(pt)
		except Exception as e:
			print e



if __name__ == "__main__":
	main(sys.argv)
