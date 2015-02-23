#!/usr/bin/env python

# The matasano crypto challenges - Set 5 Challenge 39 (http://cryptopals.com/sets/5/challenges/39/)
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


# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *



def main(argv):
    pubkey, privkey = RSA_generate_keypair(128)

    pt = 42
    ct = RSA_encrypt_int(pt, pubkey)
    npt = RSA_decrypt_int(ct, privkey)

    if pt == npt:
        print "OK"
    else:
        print "FAIL"

    pt = "This is a plaintext message"
    ct = encrypt_block_ECB(pt, 16, pubkey, encrypt_block_RSA)
    npt = decrypt_block_ECB(ct, 16, privkey, decrypt_block_RSA)

    if pt == npt:
        print "OK"
    else:
        print "FAIL"


if __name__ == "__main__":
    main(sys.argv)