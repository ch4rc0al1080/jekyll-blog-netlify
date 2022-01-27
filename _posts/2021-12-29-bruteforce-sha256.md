---
layout: article
pageview: true
key: 2021-12-29-bruteforce-sha256
title: 爆破sha256前四位脚本
author: Ch4rc0al
categories: 
    - Tips
tags: 
    - CTF
    - Pwn
---



有的CTF题目需要爆破sha256字符串的前四位，如果写暴力脚本则效率较低，提前生成字符串可以提高效率
<!--more-->

以下脚本采用多线程爆破

```python
import hashlib
import threading
import itertools

alpha_bet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
strlist = itertools.product(alpha_bet, 4)


sha256="a645e3deef85766e43c8a1aa63d1f69eed55e7cb94f10973bd76a9ace57c7311"
tail="amLSvne0g1ypVG5J"


xxxx=''
flag=0

def bruce(data):
    global xxxx
    global flag
    data_sha=hashlib.sha256((data+str(tail)).encode('utf-8')).hexdigest()
    print(data)
    if(data_sha==sha256):
        xxxx=data
        flag=1

threads=[]
for i in strlist:
    if(flag==1):
        break
    data=i[0]+i[1]+i[2]+i[3]
    t=threading.Thread(target=bruce,args=(data,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print(xxxx)
```