# 取证

## 磁盘取证

### 一些基础使用的命令行工具

#### ps

列出所有用户的进程（a）,并显示所属用户名（u）,另外还包括没有绑定终端的（x）.

```shell
$ ps aux
```
显示所有进程完整的列表

```shell
$ ps ef
```

#### lsof
查看指定进程详细信息，包括与之相关的文件和端口。

```shell
$ lsof -p
```
查看进程运行状态或者正在访问的文件：

```shell
$ lsof +L1
```

#### find
查找命令

```shell
$ find / -uid 0
```

### arp

查看所有系统的MAC&IP地址映射

```shell
$ arp -a
```


其他一些命令: uptime, free, df.

### dd

### strings

```shell
$ strings /tmp/mem.dump | grep BOOT_
$ BOOT_IMAGE=/vmlinuz-3.5.0-23-generic
```



### scalpel

### TrID

### binwalk

### foremost

### ExifTool

### dff

### CAINE

### The Sleuth Kit


----------

## 内存取证

### memdump



### Volatility: Analysing Dumps

* [Lots of material on Volatility and Memory Forensics here](volatility.md)
* [On OSX Memory Forensics](osx_memory_forensics.md)
* I highly recommend their training.


---------------
## Scripts

#### PDFs
测试PDF文件的工具:

- pdfid
- pdf-parser


-----------
## References

* [File system analysis](http://wiki.sleuthkit.org/index.php?title=FS_Analysis)
* [TSK Tool Overview](http://wiki.sleuthkit.org/index.php?title=Mactime)
