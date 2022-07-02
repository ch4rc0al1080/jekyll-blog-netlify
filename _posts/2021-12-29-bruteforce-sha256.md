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
只需要更改`sha256`和`tail`即可运行
<!--more-->


```python
import hashlib
import itertools
from string import digits, ascii_letters, punctuation
alpha_bet=digits+ascii_letters+punctuation
strlist = itertools.product(alpha_bet, repeat=4)

sha256="a645e3deef85766e43c8a1aa63d1f69eed55e7cb94f10973bd76a9ace57c7311"
tail="amLSvne0g1ypVG5J"

xxxx=''

for i in strlist:
    data=i[0]+i[1]+i[2]+i[3]
    data+=str(tail,encoding='utf-8')
    data_sha=hashlib.sha256(data.encode('utf-8')).hexdigest()
    if(data_sha==sha256):
        xxxx=data
        break

print(xxxx)
```