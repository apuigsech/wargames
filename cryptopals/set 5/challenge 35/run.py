#!/usr/bin/env python

# The matasano crypto challenges - Set 5 Challenge 35 (http://cryptopals.com/sets/5/challenges/35/)
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

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2


side_A_info = {}
side_B_info = {}

side_MITM_info = {}


def dh_generate_key(g, p):
    u = random.randint(0, p-1)
    return u,modexp(g, u, p)


def step_1_generate_kpub(info):
    global p
    global g
    info['u'], kpub = dh_generate_key(g, p)
    return kpub


def step_2_calc_kses(info, kpub):
    global p
    info['kses'] = sha1("{0}".format(modexp(kpub, info['u'], p)))[0:16]


def step_3_encrypt_msg(info, pt):
    iv = ''.join([chr(random.randint(0,255)) for i in range(16)])
    return iv, encrypt_block_CBC(pt, 16, iv, info['kses'], encrypt_block_AES)

def step_4_decrypt_msg(info, ct, iv):
    return decrypt_block_CBC(ct, 16, iv, info['kses'], decrypt_block_AES)



def step_3_mitm(info, iv_A, ct_A, iv_B, ct_B):
    if g == 0 or g == p:
        kses = sha1("{0}".format(0))[0:16]
    elif g == 1:
        kses = sha1("{0}".format(1))[0:16]
    else:
        return
    pt_A = decrypt_block_CBC(ct_A, 16, iv_A, kses, decrypt_block_AES)
    pt_B = decrypt_block_CBC(ct_B, 16, iv_B, kses, decrypt_block_AES)
    print "[intercepted] A->B:", pt_A
    print "[intercepted] B->A:", pt_B


def simulate_communication(mitm, new_g=None):
    if mitm and new_g != None:
        global g
        g = new_g

    kpub_A = step_1_generate_kpub(side_A_info)
    kpub_B = step_1_generate_kpub(side_B_info)

    step_2_calc_kses(side_A_info, kpub_B)
    step_2_calc_kses(side_B_info, kpub_A)


    iv_A, ct_A = step_3_encrypt_msg(side_A_info, "this is a msg from A to B")
    iv_B, ct_B = step_3_encrypt_msg(side_B_info, "this is a msg from B to A")

    if mitm:
        step_3_mitm(g, iv_A, ct_A, iv_B, ct_B)

    print "A->B:", step_4_decrypt_msg(side_B_info, ct_A, iv_A)
    print "B->A:", step_4_decrypt_msg(side_A_info, ct_B, iv_B)


def main(argv):
    print "COMMUNICATION WITHOUT MITM"
    simulate_communication(False)

    print "COMMUNICATION WITH MITM (g=0)"
    simulate_communication(True, 0)

    print "COMMUNICATION WITH MITM (g=1)"
    simulate_communication(True, 1)

    print "COMMUNICATION WITH MITM (g=p)"  
    simulate_communication(True, p)



if __name__ == "__main__":
    main(sys.argv)
