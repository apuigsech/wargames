#!/usr/bin/env python

# The matasano crypto challenges - Set 5 Challenge 33 (http://cryptopals.com/sets/5/challenges/33/)
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

def modexp (g, u, p):
	s = 1
	while u != 0:
		if u & 1:
			s = (s * g)%p
		u >>= 1
		g = (g * g)%p;
   	return s

def main(argv):
    p = 37
    g = 5
    a = random.randint(0, p-1)
    A = (g**a)%p
    b = random.randint(0, p-1)
    B = (g**b)%p

    s1 = (A**b)%p
    s2 = (B**a)%p

    if s1 == s2:
        k = s1
        print "Key:", sha1("{0}".format(k)).encode('hex')


	p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
	g = 2
    a = random.randint(0, p-1)
    A = modexp(g,a,p)
    b = random.randint(0, p-1)
    B = modexp(g,b,p)

    s1 = modexp(A,b,p)
    s2 = modexp(B,a,p)

    if s1 == s2:
        k = s1
        print "Key:", sha1("{0}".format(k)).encode('hex')


if __name__ == "__main__":
    main(sys.argv)
