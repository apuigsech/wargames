#!/bin/sh
#
# Boston Key Party 2015 - Crypto Airport (http://bostonkey.party/)
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
import os
import socket
import hashlib
import time
from bitstring import BitArray

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *


SAFEPRIME = 27327395392065156535295708986786204851079528837723780510136102615658941290873291366333982291142196119880072569148310240613294525601423086385684539987530041685746722802143397156977196536022078345249162977312837555444840885304704497622243160036344118163834102383664729922544598824748665205987742128842266020644318535398158529231670365533130718559364239513376190580331938323739895791648429804489417000105677817248741446184689828512402512984453866089594767267742663452532505964888865617589849683809416805726974349474427978691740833753326962760114744967093652541808999389773346317294473742439510326811300031080582618145727L


def proof_of_work(s):
	pow_base = s.recv(12)
	while True:
		nonce = os.urandom(8)
		block = pow_base + nonce
		ha = hashlib.sha1(block)
		if ha.digest().endswith('\xff\xff\xff'):
			print ha.hexdigest()
			s.send(block)
			return


def timming_oracle(s, bits):
	for b in [0,1]:
		e = BitArray(bits + [b]).uint
		x = rootmod(e, 4, SAFEPRIME)
		if x != None:
			before = time.time()
			s.send(str(x))	
			r = s.recv(1024)
			after = time.time()
			if (after - before > 1):
				return b
	return None


def main(argv):
	if len(argv) < 3:
		print "Missing arguments."
		sys.exit(0)

	TCP_IP = argv[1]
	TCP_PORT = int(argv[2])

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((TCP_IP, TCP_PORT))

	proof_of_work(s)

	bits = [1]
	while True:
		b = timming_oracle(s, bits)
		if b == None:
			break
		bits += [b]
		sys.stdout.write("SECRET = {0}\r".format(bits))
		sys.stdout.flush()
	print "\n"

	flag = None
	for b in [0,1]:
		e = BitArray(bits + [b]).uint
		x = rootmod(e, 4, SAFEPRIME)
		if x != None:
			s.send(str(x))
			r = s.recv(1024)
			if r.isdigit() == False:
				flag = r

	print "FLAG = {0}".format(flag)


if __name__ == "__main__":
	main(sys.argv)