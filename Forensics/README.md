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
拷贝文件并转换

### strings 
查找字符串

```shell
$ strings /tmp/mem.dump | grep BOOT_
$ BOOT_IMAGE=/vmlinuz-3.5.0-23-generic
```



### scalpel 文件分割器

### TrID 文件类型分析工具

### binwalk 后门（固件）分析工具

### foremost 文件恢复工具

### ExifTool 图片信息查看工具

### dff （Digital Forensics Framework）恢复丢失文件，证据分析

### CAINE 填补不同工具间的互操作间隙

### The Sleuth Kit 分析磁盘映像，恢复文件


----------

## 内存取证

### 内存显示备份文件系统



### Volatility分析镜像文件: 分析备份文件系统

* [更多关于分析镜像，备份文件系统的信息](volatility.md)
* [OSX系统内存取证](osx_memory_forensics.md)
* 强烈推荐他们的练习.


---------------
## 脚本

#### PDFs
测试PDF文件的工具:

- pdfid
- pdf-parser


-----------
## 参考文献

* [文件系统分析](http://wiki.sleuthkit.org/index.php?title=FS_Analysis)
* [TSK工具概述](http://wiki.sleuthkit.org/index.php?title=Mactime)
