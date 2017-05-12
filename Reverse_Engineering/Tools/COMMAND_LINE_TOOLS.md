命令行工具
==================


### 小技巧:

- 文件的文件名带有空格和有符号链接的文件


### 查找


```
grep word f1

sort | uniq -c

diff f1 f2

find -size f1
```


### 编码/二进制

```
file f1

ltrace bin

strings f1

base64 -d

xxd -r
```



### 压缩文件


```
zcat f1 > f2

gzip -d file

bzip2 -d f1

tar -xvf file
```



### 连接服务器/端口

```
echo 4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e | nc localhost 30000

openssl s_client -connect localhost:30001 -quiet

nmap -p 31000-32000 localhost

telnet localhost 3000
```



