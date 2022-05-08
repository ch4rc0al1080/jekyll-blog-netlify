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

在`libc-2.33`中，对于fastbin以及tcache的fd指针会被进行异或操作加密，用来异或的值随堆地址发生改变。