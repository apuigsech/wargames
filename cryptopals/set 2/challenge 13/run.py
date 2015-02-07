#!/usr/bin/env python

# The matasano crypto challenges - Set 2 Challenge 13 (http://cryptopals.com/sets/2/challenges/13/)
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
import re

# Cryptohelper from https://github.com/apuigsech/cryptohelper
from cryptohelper import *

key = ''.join([chr(random.randint(0,255)) for i in range(16)])

def profile_for(email):
	if re.match('.[=&].', email):
		return None
	profile = {
		'email': email,
		'uid': 10,
		'role': 'user'
	}
	query_str = 'email={0}&uid={1}&role={2}'.format(profile['email'], profile['uid'], profile['role'])
	return encrypt_block_ECB(query_str, 16, key, encrypt_block_AES)


def encrypt_data(data):
	fake = "A"*10 + data
	numblocks = int(math.ceil(float(len(data))/16))
	ct = profile_for(fake)
	return block_join(block_split(ct,16)[1:numblocks+1])


def tamper_data(ct, fakedata, idx):
	if len(fakedata) % 16 != 0:
		fakedata = data_pad_PKCS7(fakedata, 16)
	fakect = encrypt_data(fakedata)
	fakect_blocks = block_split(fakect, 16)
	ct_blocks = block_split(ct, 16)
	for i in range(idx,idx+len(fakect_blocks)):
		ct_blocks[i] = fakect_blocks[i-idx];
	return block_join(ct_blocks)



def main(argv):
	ct = profile_for("fake@mail.com")

	newct = tamper_data(ct, "admin", 2)

	print decrypt_block_ECB(newct, 16, key, decrypt_block_AES)



if __name__ == "__main__":
   main(sys.argv)

