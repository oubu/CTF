# Linux Hacking

## 提权

* [多年以来Unix特权是如何升级利用的](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack).

## 附件文件夹

### SSH攻击

- 从内存中获取未加密的ssh密钥


### Shellshock

- scripts
- POCs

---

## UNIX利用

### RPC Daemons

* rexd (远程执行): 远程用户如同本地用户般执行程序

* rshd, rlogind, sshd: 对基于源IP地址的建立关系高度信任


---

## 关于Linux的指南和技巧

# Linux环境


## Linux文件系统

* 让我们来了解我们的Linux系统。Linux文件系统由根目录（/）下多个系统目录构成：

```
$ ls /
```

* 你可以使用如下命令验证他们的大小和挂载点：
```
$ df -h .
Filesystem              Type  Size  Used Avail Use% Mounted on
/dev/mapper/fedora-home ext4  127G   62G   59G  51% /home
```

## Linux文件系统框架分为以下几个目录：

### /bin, /sbin and /user/sbin
* **/bin** 目录包含可执行文件，单用户模式下及所有系统用户的基本命令。
* **/sbin**目录包含单用户模式系统非基本的命令 

### /dev
* **/dev** 目录包含设备节点（一种被大多数硬件和软件设备使用的为文件，网络设备除外） 

* 目录还包括由udev系统生成的条目。（dev系统负责生成和管理Linux系统的设备节点，通常能够在发现设备时自动生成）

### /var
* **/var**是variable的简称，该目录包含系统运行过程中可变化大小和内容的文件。
* 例如， 系统日志文件位于**/var/log**目录下, 包与数据库文件位于 **/var/lib**目录下,打印序列位于**/var/spool**目录下, 临时文件位于**/var/tmp**目录下,另外可以在**/var/ftp** 和**/var/www**等子目录下找到网络服务相关的文件

### /etc

* **/etc**代表系统配置文件。该目录不包含二进制程序，但是会有一些可执行的脚本。

* 例如**/etc/resolv.conf**文件 包含主机名和相应的IP地址来完成DNS解析工作。
* 另外t**/etc/passwd** 文件包含所有Unix系统上用户的认证信息，但其中不包含密码：经加密的密码信息已经被转存于**/etc/shadow**文件中。

### /lib
* **/lib** 包含**/bin** 和 **/sbin**目录下基本程序的库(应用运行所需要并且相互共享的公共代码)。

* 这些库文件名称通常以```ld```或者```lib``` 开头并且被称作*动态链接库*（或者共享库）

### /boot

* **/boot** 目录包含引导系统所需要的最基本的文件。
* 安装在系统上每一个可替换的内核都包含4个文件：

    * ```vmlinuz```: 引导所需要的压缩的Linux内核。

    * ```initramfs``` or ```initrd```: 引导所需要的初始内存文件系统。
    * ```config```: 调试所需要的内核配置文件。

    * ```system.map```: 内核标志表。

    * [GRUB](http://www.gnu.org/software/grub/) 在这里也可以找到文件。

### /opt
* 可选的应用软件包目录。该目录下的软件通常由用户手动安装。

### /tmp
* **/tmp**目录包含一些临时文件，这些临时文件在重启后将被删除。 

### /usr

* **/usr** 目录包含多用户的应用、插件和数据。通常子目录有：
    * **/usr/include**: 编译应用所用的头文件。

    * **usr/lib**: 包含**usr/(s)bin**目录下程序的库文件。

    * **usr/sbin**: 包含非必须的系统二进制文件，例如系统守护进程n。在目前的Linux系统中通常被链接至 **/sbin**目录。

    * **usr/bin**: 系统可执行命令的主要目录。
    * **usr/share**: 被应用所使用的shaped数据, 通常是平台无关的。
    * **usr/src**: 通常为Linux内核的源码。

    * **usr/local**: 针对本机的数据和程序。


---
## /dev Specials

* 存在操作系统提供的文件。这些文件虽然不代表任何物理设备, 但是使得用户能访问特殊功能。
    * **/dev/null** 忽略任何写入的文件。 方便用于丢弃不要的输出。
    * **/dev/zero** 包含一个无数个0字节*。可用于创建指定长度的文件。
    * **/dev/urandom** and **/dev/random** 都包含无限个操作系统生成的随机数。对于所有应用程序都可访问。 两者的区别在于后者随机性更强，因此可用于加密。而前者只可用于游戏。
* 例如使用一下命令即可输出随机数:

```
$ cat /dev/urandom | strings
```



## The Kernel

*  **Linu内核** 是管理来自软件*输入/输出请求* 并编译成CPU可执行的*数据处理指令* 的程序。

* 如何查找内核信息?

```
$ cat /proc/version
Linux version 3.14.9-200.fc20.x86_64 (mockbuild@bkernel02.phx2.fedoraproject.org) (gcc version 4.8.3 20140624 (Red Hat 4.8.3-1) (GCC) ) #1 SMP Thu Jun 26 21:40:51 UTC 2014
```

* 你也可以通过指定的命令```uname```来查看类似的系统信息：

```
 $ uname -a
 Linux XXXXX 3.14.9-200.fc20.x86_64 #1 SMP Thu Jun 26 21:40:51 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```

* 例如，你可能想要验证你是否使用最新的内核。你可以通过查看如下两个命令输出是否一致来确认：

```
$ rpm -qa kernel | sort -V | tail -n 1
$ uname -r
```

* 另外，对于Fedora(以及其他RPM系统)你可以使用如下命令查看安装的内核情况：

```
$ rpm -q kernel
```


---
## Processes

* 正在运行的程序被称作**process**（进程）。每个进程都有一个**owner**（所属用户）。（这和我们下面谈到的文件权限一样）
* 通过**ps**命令你可以知道那些程序在运行。命令的输出也列出**process ID** 或者称 **PID**。这是某个进程的唯一标识（也是长期的）。如果对某个程序进行复制，每个进程将会分的不同的PID。

* 为了将一个任务或进程放到后台,我们可以使用**&**来操作或者我们可以按下CTRL-Z然后输入**bg**.输入**fg**可以将其释放到前台.

* 我们可以输入**jobs**以得到shell中运行的任务列表.每个任务都有一个**job ID**可以和百分号**%**一起在**bg**,**fg**或是**kill**中使用(这些在后文会有详细介绍).


### ps

* 想要查看非当前会话启动的进程可以执行如下命令:

```
$ ps x
```

* 查看当前用户与其他用户进程:

```
$ ps aux
```

* 列出所有僵尸进程:

```
$ ps aux | grep -w Z
```

或是

```
$ ps -e
```


### top

* 另一个有用的命令是**top** (table of processes)。它能告诉你占用内存和CPU最高的是那些进程。 
```
$ top
```

* 我特别喜欢 [htop](http://hisham.hm/htop/) 命令，甚至胜过了top命令。htop命令需要安装才能使用。

### kill

*  你可以使用**kill**命令来结束运行的程序。 这个命令将向程序发送称为 **signal**（信号量）的消息。 有[64种不同的信号量](http://www.linux.org/threads/kill-commands-and-signals.4423/), 每一种信号量都有不同的意义:

```
$ kill <ID or PID>
```

* kill命令默认发送的信号量是**SIGTERM**,告诉程序你想要退出 。这只是一个请求，程序可以选择忽视他。

* 信号量 **SIGKILL** 具有强制性，能够立刻终止某个进程。但是也存在特殊情况，比如进程正处于在向操作系统的某个请求中（例如某种系统调用），而请求需要先完成。**SIGKILL**是信号量列表中第9个，因此往往通过以下形式命令发送信号量。
```
$ kill -9 <ID or PID>
```

* CTRL-C组合键是一个退出进程更加简单的方式 ，它发送的信号量为**SIGINT**。你也可以指定一个PID座位参数。


### uptime

* 另一个好用的命令是 **uptime**。它能够给出系统运行的时间，同时也能计算出系统的平均负载。
```
$ uptime
```

### nice and renice

*  最后介绍的是```nice``` 和```renice```。你可以使用使用这两个命令来修改进程的优先级。其中nice命令使用计划变更的优先级运行某个程序，而renice直接修改某个运行中进程的优先级。


---
## 环境变量

* *Environment variables*（环境变量） 是一些操作系统中可被用于运行中进程的动态命名变量。 


### set与env
*  你可以在系统中使用如下命令查看环境变量和配置：

```
$ set
```
或者
```
$ env
```

### export与echo
* 使用如下命令可以修改环境变量的值：

```
$ export VAR=<value>
```

* 使用echo命令即可检查环境变量的值：

```
$ echo $VAR
```

*  **PATH** (搜索路径) 是一些供shell寻找命令的目录。 例如当你输入 ```ls```命令后，它将查看```/bin/ls```。 目录被存储在环境变量**PATH**中,这些目录被冒号分割并且被编码在文件**./bashrc** 中。你可以使用以下命令来增加一个新目录。
```
$ export PATH=$PATH:/<DIRECTORY>
```

### 脚本中的变量

* 在一个运行的shell脚本中，有称为**$1**和**$2**等等的虚拟环境变量，这些变量对应相应的被传入脚本的参数。另外**$0**代表脚本的名字，**$@**代表所有命令行参数的列表。 


---
##  "~/." 文件 (dot-files)

* 某些文件的文件名前带有一个点号（英文句号）。在这里点号表明不该正常列出这些文件，除非特别地指明需要列出这些文件。这是因为dot-files（点号文件）通常用于存储应用功能的配置和敏感信息。

### ~/.bashrc

* **~/.bashrc**包含bash被调用后执行的脚本和变量。
* 自定义你的 **~/.bashrc**文件是一种很棒的体验. 可以google一下或者看下[site dedicated for sharing dot-files](http://dotfiles.org)以及 [mine](https://github.com/mariwahl/Dotfiles-and-Bash-Examples/blob/master/configs/bashrc)。不要忘了每次你更改**./bashrc**文件后使用```source``` 命令（重新打开一个终端也有同样的效果):

```
$ source ~/.bashrc
```

### 重要的dot-files

* 如果你使用具有加密功能的程序I例如 [ssh](http://en.wikipedia.org/wiki/Secure_Shell) 和 [gpg](https://www.gnupg.org/), 你会在目录**~/.ssh** 和**~/.gnupg**下找到它们存储的大量的信息。
* 如果你是*Firefox* 用户, **~/.mozilla**目录包含了你web浏览器的历史记录、书签、cookie和任何被保存的密码。

* 如果你使用 [Pidgin](http://pidgin.im/), **~/.purple** 目录 ([the IM library](https://developer.pidgin.im/wiki/WhatIsLibpurple)) 包含隐私信息。其中包括敏感的Pidgin加密扩展（比如 [Off-the-Record](https://otr.cypherpunks.ca/)）的用户密钥。


---
## 文件描述符

* **file descriptor** (文件描述符) 是访问I/O资源所使用的数字描述符。其值如下：
    * fd 0: stdin (标准输入).
    * fd 1: stdout (标准输出).
    * fd 2: stderr (标准错误).

* 这种命名方式用于在命令行中操作这些资源。例如，可以使用 **<**将输出重定向到某个程序：

```
$ <PROGRAM> < <INPUT>
```

* 你可以使用**>**向终端以外（例如文件）发送程序的**output**，例如，仅仅删除输出:

```
$ <PROGRAM> > /dev/null
```

* 你可以使用“file descriptor 2”向文件发送程序错误信息:

```
$ <PROGRAM> 2> <FILE>
```

* 为了向**stdout**正在运行的地方发送程序错误的信息，*i.e.*将其并入一个字串流（这在导管输送中极为有效）:

```
$ <PROGRAM> 2>&1
```

----
## 文件权限

* 在Linux中每一个文件或目录据说都属于一个特定的**owner**和一个特定的**group**.文件可以在操作被允许的地方进行声明.


### 改变文件或目录访问权限
* 资源会有三个权限：只读，可写和执行:

    * 对于一个文件来说,这些权限是阅读文件,修改文件和以程序运行文件.

    * 对于目录来说,这些权限则是：列出目录内容,创建或删除目录中的文件和访问目录中的文件.

* 使用```chmod```命令以改变权限.


### 改变文件所属的用户和组

* Unix权限模型不支持*access control lists*命令以出于特定目的与枚举用户列表分享文件.因此,管理员需要将所有用户拉入一个特殊组别使得文件属于这个组别.文件的拥有者将不能随意分享文件.


* 关于资源有三个操作者：使用者,特定组别和所有人.每一个都有他们相分割的权限来浏览,编辑和执行文件.

* 你可以使用```chown```来改变资源的拥有者.有两种方法来设置改变权限的权限:

    * 使用八进制数字形式模式: read = 4, write = 2, execute = 1, 以及 user = x100, group = x10, all = x1,并且求出授予权限对应的值.例如755 = 700 + 50 + 5 = rwxr-xr-x: ``` $ chmod 774 <FILENAME>```

    * 使用符号模式缩写letter-based形式:字母u, g,或a,其次是加减,再其次是字母r,w,或x. u+x代表着"授予用户执行权限", g-w表示"否认组别拥有写入权限",以及a+r代表"授予所有人阅读权限":```$ chmod g-w <FILENAME>```.


* 你可以使用```chgrp```来改变组别,与改变权限是一样的逻辑.



* 如果想要在最近的文件夹里查看文件的权限，需要输入:

```
$ ls -l
```

* 例如,```-rw-r--r--```表示这是文件(-)拥有者阅读(r)编辑(w)的权限,但是并没有执行权限(-).


---

#  Shell Commands 和 Tricks

## 浏览文件

### cat

* 在终端打印文件内容:

```
$ cat <FILENAME>
```

### tac

* 在终端颠倒着打印文件内容（从底部开始）:

```
$ tac <FILENAME>
```

### less 和 more

* 两者都是打印文件内容，但是加入了页数控制:

```
$ less <FILENAME>
$ more <FILENAME>
```

### head 和 tail
* 从开头浏览20行:

```
$ head -20 <FILENAME>
```

* 从底部浏览20行:

```
$ tail -10 <FILENAME>
```

### nl

* 打印含有行数数字的文件:

```
$ nl <FILENAME>
```

### tee

* 保存文件的输出并使它可见:

```
$ <PROGRAM> | tee -a <FILENAME>
```

### wc

* 打印文件的长度和行数:

```
$ wc <FILENAME>
```



---
## Searching inside Files
在文件中搜索

### diff 和 diff3

* **diff**可以用来比较文件和目录.实用的参数包括：**-c**列举不同之处,**-r**递归比较子目录,**-i**忽略大小写,**-w**忽略空格和符号.

* 你可以立刻使用**diff3**来比较三个文件，其中一个文件被用以作为另外两个的参考依据.


### file

* 命令**file**展现了文件的真实属性:

```
$ file requirements.txt
requirements.txt: ASCII text
```

### grep
* **grep**寻找特定搜索模式匹配.参数**-l**列举包含匹配的文件,参数**-i** 使得搜索对于大小写非常敏感,**-r**搜索所有目录以及子目录里的文件:

```
$ grep -lir <PATTERN> <FILENAME>
```

* 例如,移动整行并不等于移动一个词:

```
$ grep -xv <WORD> <FILENAME>
```

---
## Listing or Searching for Files


### ls

* **ls**列出目录和文件.实用的参数**-l**用以列出目录中的每个文件的权限,**-a**把dot文件列入:

```
$ ls -la
```

* 根据大小排序文件:

```
$ ls -lrS
```

* 列出最近修改的10个以.txt结尾的文件的文件名:

```
$ ls -rt *.txt | tail -10
```


### tree

* **tree**命令用以列举树形图中目录的内容.


### find

* 在目录中查找文件:

```
$ find <DIRECTORY> -name <FILENAME>
```

### which

* 查找二进制文件的路径变量:

```
$ which ls
```

### whereis

* 在任意目录中查找文件:

```
$ whereis <FILENAME>
```

### locate

* 按文件名查找文件（使用数据库）:

```
$ locate <FILENAME>
```

* 如果文件存在就加以检验:

```
$ test -f <FILENAME>
```

---
## Modifying Files
 修改文件

### true

* 清空文件:
```
$ true > <FILENAME>
```

### tr

*  **tr**用一双字符串作为参数和替换，在这里的输入中，每个在第一个字符串中出现的字母由第二个字符串中相应的字符替换.例如，使每个字母降级:

```
$ tr A-Z a-z
```

* 通过用新行替换空格在每一行中放入单词:

```
$ tr -s ' ' '\n'
```

* 混合多行成为独立的一行:


```
$ tr -d '\n'
```

* **tr**不接受文件的名称来运作,所以我们可以运用cat输入文件内容（与```$ <PROGRAM> < <FILENAME>```同效）:

```
$ cat "$@" | tr
```

### sort

* 将文本文件排序.**-r**按背景排序，**-n**选择数字化排序（例如,如果没有它，2会在1000之后）：

```
$ sort -rn <FILENAME>
```

* 输出频率计数（按柱状图形式）:

```
$ sort <FILENAME> | uniq -c | sort -rn
```

* 从文件中随机选取数行：

```
$ sort -R  <FILENAME> | head -10
```

* 合并多个文件成为一个整理好的文件:

```
$ sort -m <FILENAME>
```

### uniq


* **uniq**移动相邻的重复行.**-c**将其列入单独列表:

```
$ uniq -c <FILENAME>
```

* 输出只重复两次的行:

```
$ uniq -d <FILENAME>
```

### cut

* **cut**从有结构的文本文件中选择特定的字段（列）（或是从任意文本文件中每一行选取特定的字符）.**-d**指定定界符分割列的位置（默认选项卡）,**-f**指定需要打印的字段以及打印的顺序:

```
$ cut -d ' ' -f 2 <FILENAME>
```

* **-c**指定输出的字符范围,所以**-c1-2**只输出每一行的开头两个字符:

```
$ cut -c1-2 <FILENAME>
```

### join
* **join**通过常见的分隔字段组合多个文件:

```
$ join <FILENAME1> <FILENAME2>
```




----
## Creating Files and Directories

### mkdir

* **mkdir**创建目录.一个实用的**-p**可以创建目录的完整路径（以防万一它们不存在）:

```
$ mkdir -p <DIRNAME>
```

### cp

* **cp**用以复制目录.**-a**保留所有的元数据:

```
$ cp -a <ORIGIN> <DEST>
```

* 有趣的是,**$()**中包含的命令可以运行,命令的输出由条款代替,还可以被用作另一个命令行的部分:

```
$ cp $(ls -rt *.txt | tail -10) <DEST>
```


### pushd and popd

* **pushd**命令用以在内存中保存最近的工作目录所以可以在任意时间返回,选择性转变为新的目录:

```
 $ pushd ~/Desktop/
```

* **popd**命令返回路径在目录堆栈的顶部.

### ln

* **ln**用来以不同名字关联文件.你可以使用**-s**创建一个符号（软）链接:

```
$ ln -s <TARGET> <LINKNAME>
```


### dd

* **dd**对于磁盘到磁盘的复制很有用,原始磁盘空间的复制也有很大用处.例如,备份你的 [主引导记录](http://en.wikipedia.org/wiki/Master_boot_record) (MBR):

```
$ dd if=/dev/sda of=sda.mbr bs=512 count=1
```

* 用**dd**从磁盘向另一个磁盘进行复制:

```
$ dd if=/dev/sda of=/dev/sdb
```



----
## Network and Admin

### du

* **du**显示每个文件所占用的磁盘空间:

```
$ du -sha
```

* 显示信息分类及10个最大的文件:

```
$ du -a | sort -rn | head -10
```

* 确定哪些子目录正在占用大量的磁盘空间:

```
$ du --max-depth=1  | sort -k1 -rn
```

### df

* **df**显示每个挂载文件系统所占用的磁盘空间. 每个文件系统显示5列: 文件名,大小,使用次数,可用大小,使用百分比,安装地点. 注意值不会增加因为Unix文件系统有只有根用户才能写入的**reserved**存储日志.

```
$ df -h
```



### ifconfig

* 你可以检查和配置网络接口:

```
$ ifconfig
```

* 总体而言,当你使用**ifconfig**时,你将会看到下列设备:

    * ***eth0***:显示以太网卡上的信息例如: 硬件地址,IP地址,网络掩码.

    * ***lo***:环回地址或本地主机.


* **ifconfig**可能会被否决. 查看 [我的短ip-netns指南](https://coderwall.com/p/uf_44a).


### dhclient

* Linux的DHCP服务器运行一个守护进程称为```dhcpd```,将IP地址分配给所有子网上的系统(也使日志文件如此):

```
$ dhclient
```

### dig


* **dig**是一个DNS查找工具(类似于Windows中的```dnslookup```).

### netstat


* **netstat**打印网络连接、路由表、接口数据等。实用的参数是TCP的**-t**,UDP的**-u**,听方面的**-l**,项目的**-p**,数字的**-n**.例如:

```
$ netstat -tulpn
```



### netcat, telnet and ssh

* 为了连接到主机服务器,可以使用**netcat**(nc)和**telnet**。**ssh**用以连接一个加密的会话.例如,将字符串发送到主机的3000端口上:

```
$ echo 4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e | nc localhost 3000
```

* 在3000端口上远程登录到本地主机:

```
$ telnet localhost 3000
```



### lsof

* **lsof**列出公开文件(记住,一切都被认为是一个Linux下的文件):

```
$ lsof <STRING>
```

* 查看公开的TCP端口:

```
$ lsof | grep TCP
```

* 查看IPv4端口:

```
$ lsof -Pnl +M -i4
```

* 查看IPv6列表端口:

```
$ lsof -Pnl +M -i6
```



---

## Useful Stuff

### echo


* **echo**打印它的参数作为输出.对于传输途径它可能是有用的,在这种情况下,使用**-n**不输出新行:
```
$ echo -n <FILENAME>
```

* **echo**对于脚本中生成命令有用(记得讨论文件描述符):

```
$ echo 'Done!' >&2
```

* 或查找shell环境变量(记得讨论):

```
$ echo $PATH
```

* 例如,我们可以向文件发送最近的数据信息:

```
$ echo Completed at $(date) >> log.log
```

### bc

* 命令**bc**给出计算机程序,**-l**代表标准的数据库:

```
$ bc -l
```

* 例如,我们可以用它进行快速的计算:
```
$ echo '2*15454' | bc
30908
```



### w, who, finger, users


* 你可以使用**w, who, finger**和**users**命令来查找关于登录用户的信息.





---
## Regular Expression 101

* **Regular expressions**正则表达式(regex)的字符序列,形成一个搜索模式用于模式匹配字符串.

*  字母和数字匹配。因此,'awesome'是一个正则表达式匹配'awesome'.

* 可以和**grep**一同使用的主要规则为:
    * ```.``` 匹配任何字符.
    * ```*``` 任何的次数(包括零).
    * ```.*``` 匹配任意字符串(包括空串).
    * ```[abc]``` 匹配任何字符a或b或c.
    * ```[^abc]``` 匹配任何字符除却a或b或c.
    * ```^``` 匹配一行的开始.
    * ```$``` 匹配一行的结尾.

* **^**例如,发现在一个文件中可以从一个特定的字符串可以使用正则表达式符号**^**:

```
$ grep ^awesome
```

* 此外,查找以一个特定的字符串结束的行可以使用**$**:

```
$ grep awesome$
```

*  As an extension,  uses a version called *extended regular expresses* (EREs) which include things such作为扩展,**egrep**使用一个叫做*extended regular expresses*(扩展正则表达)的版本来包含这类事情:
    * ```()``` 对于分组
    * ```|``` 或者
    * ```+``` 一次或多次
    * ```\n``` 反向引用(在这个表达式中，引用括号组数字n之前的任何匹配的副本).

* 例如,可以使用``` egrep '.{12}'```找到至少12个字母的单词。您可以使用```egrep -x '.{12}'```找到由十二个字母构成的单词.




---

## Awk and Sed

* **awk**是一个模式扫描工具而**sed**是过滤和转换文本流编辑器.虽然这些工具非常强大, 但是如果你有任何高水平的语言知识如Python或Ruby, 那么你不就需要学习它们这些工具.

### sed

* 假设我们想用mysql取代每个*mysql*(Linux大小写敏感), 然后保存新文件<FILENAME>. 我们可以写一个单行命令说“搜索词mysql,代之以MySQL”:

```
$ sed s/mysql/MySQL/g <FILEORIGIN> > <FILEDEST>
```

* 用这个目录中每个文件后跟单独空间的一段时期来替换后跟任意数量空间的任何时期的实例:

```
$ sed -i 's/\. */. /g' *
```

*在打印出第一个参数指定的脚本行数后通过一个输入流编辑器然后放弃:

```
$ sed ${1}q
```



----

# Some More Advanced Stuff
一些更高级的东西

## Scheduling Recurrent Processes
调度过程

### at
* 一个非常可爱的bash命令**at**, 允许你稍后运行流程(以CTRL + D结束）:

```
$ at 3pm
```


### cron
* 如果你需要定期运行过程, 你应该使用**cron**, 像这样运行[系统守护进程](http://en.wikipedia.org/wiki/Daemon_%28computing%29).你可以在任务列表中添加一个文件命名为**crontab**用被称为**crontab**的程序运行列表. **cron**检查所有安装的定时任务文件并运行计划文件作业.

* 查看你的定时任务的内容并运行:

```
$ crontab -l
```

* 编辑你的定时任务的内容并运行:

```
$ crontab -e
```

* 配置文件的格式: *min, hour, day, month, dow* (以数字表示周几,周日是0). 他们由制表符或空格隔开. 标志*代表任意.可以指定用逗号代替许多值.

* 例如,每天早上5点运行备份,编辑你的定时任务:

```
0 5 * * * /home/files/backup.sh
```

* 或者你想要记住一些人的生日,你可以编辑你的定时任务:

```
* * 16 1 * echo "Remember Mom's bday!"
```


---
##  rsync

*  **rsync**执行文件同步和文件传输.使用*zlib*可以进行压缩转移数据,也可以使用SSH或是[stunnel软件](https://www.stunnel.org/index.html) 进行加密传输.

* 当递归地复制一个目录树到另一个时**rsync**非常有效因为这些差别只在网络上传输.

* 实用的命令是: **-e**像远程shell一样指定SSH, **-a**用于归档模式, **-r**用于递归到目录,以及**-z**用于压缩文件数据.

* **-av**是一个很常见的设置可以使得**rsync**递归地工作,它保留有关文件的元数据复制,显示正在复制的每个文件的名称.例如,下面的命令是用来传输一些目录到远程主机上的**/planning**子目录:

```
$ rsync -av <DIRECTORY> <HOST>:/planning
```



----
## 文件压缩

* 从历史上看, **tar**代表磁带归档,用于利用磁带归档文件.在今天**tar**用于允许你从一个通常称为**tarball**的归档文件中创建或提取文件.

* 此外你可以添加*file compression*,通过在文件中查找冗余之处(例如重复的字符串)以及创建更多文件内容的简洁表达来工作.最常见的压缩程序是**gzip** 和**bzip2**.
 
 * 使用**tar**时,**f**必须是最后选择.不需要连字符.你可以添加**v**作为详细阐述.

* 使用**c**指令可以生成一个简单的打包工具:

```
$ tar cf <FILE.tar> <CONTENTS>
```

* 使用**x**指令可以解压:

```
$ tar xf <FILE.tar>
```

### gzip


* **gzip**是Linux最常用的实用压缩程序.使用**z**可以用gzip来进行文件的归档或是解压:

```
$ tar zcf <FILE.tar.gz>
```

* 你可以用```zcat, zmore, zless, zgrep, zegrep```直接对gzip压缩的文件进行操作.

### bzip2

* **bzip2**创建的文件比gzip压缩的文件小得多.你可以用**j**通过bz2对文件进行归档和压缩:

```
$ tar jcf <FILE.tar.bz2>
```

### xz

* **xz**是Linux系统中使用最高效的压缩效用.使用xz以创建文件的归档和压缩:

```
$ tar Jcf <FILE.tar.xz>
```


----
## Logs

* d在```/var/log```可以看到标准日志功能.例如:
    *  ```/var/log/boot.log``` 包含系统启动时登记的信息.
    * ```/var/log/auth.log``` 包含系统授权信息.
    * ```/var/log/dmesg``` 包含内核环缓冲区信息.


* The file ```/etc/rsyslog.conf``` controls what goes inside the log files.

* 文件夹```/etc/services```是一个简单的ASCII文件,提供互联网服务的友好名称文本之间的映射,以及他们的基本分配的端口号和协议类型.检验可用以下方法:

```
$ cat /etc/services
$ grep 110 /etc/services
```

* 查看您的系统日志记录:

```
$ lastlog
```


-----
## /proc and inodes

* 如果最后一个到文件的链接被删除,但这个文件打开在一些编辑器中, 我们仍然可以获取其内容. 例如，可以这样做:
    1. 向文件被打开的程序的调试器添加例如**gdb**的指令 ,

    2. 指挥程序阅读文件描述符的内容 (**/proc**文件系统), 直接在打开的有文件描述符的伪文件里面复制文件内容.

* 例如,如果执行```$ dd if=/dev/zero of=trash & sleep 10; rm trash```命令,系统上的可用磁盘空间将继续下行(因为更多的内容在**dd**发送其输出的地址写入到文件).

* 但是, 文件在系统中任何地点都不可见!只有查看**dd**命令的执行进度会导致这个空间被回收.

* **index node** (索引节点)是一种用来表示一个文件系统对象例如文件或目录的数据结构. 一个文件的真实名称,即使它没有其他的名字, 实际上是其在文件系统中创建时的*inode number*,这可以以下列途径获得
```
$ stat
```
或是
```
$ ls -i
```

* 与一个新文件中的**ln**结果创建硬链接与 其原本的*inode number*一致.运行*rm*不会影响另一个文件:

```
$ echo awesome > awesome
$ cp awesome  more-awesome
$ ln awesome same-awesome
$ ls -i *some
7602299 awesome
7602302 more-awesome
7602299 same-awesome
```

----
## Text, Hexdump, and Encodings

* A Linux text file contains lines consisting of zero of more text characters一个Linux文本文件包含由零更多的文本字符组成的数行代码,**newline character**紧随其后(ASCII 10,也称为十六进制的0x0A或是'\n').

* 有一行含有单词'Hello'的文本ASCII是6字节 (每个字母是一个字节, 每个拖尾换行符也是一个字节). 例如以下文字:

```
$ cat text.txt
Hello everyone!
Linux is really cool.
Let's learn more!
```

代表着:

```
$ hexdump -c < text.txt
0000000   H   e   l   l   o       e   v   e   r   y   o   n   e   !  \n
0000010   L   i   n   u   x       i   s       r   e   a   l   l   y
0000020   c   o   o   l   .  \n   L   e   t   '   s       l   e   a   r
0000030   n       m   o   r   e   !  \n
0000038
```

* 左边数字显示的十六进制字节是文件中的每个输出行的偏移量.

* 不同于文本文件在其他操作系统中的情况,Linux中文件不以一个特殊的文件结束字符结束.


* Linux文本文件通常总是解释为**ASCII**.在ASCII中,每个字符是一个字节,ASCII的标准定义 **128 characters**从**ASCII 0到ASCII 127**.其中有些是非输出的(例如换行符).输出数据统计在**32**之后.既然那样,当字符位置处于**128到255**并给出外语翻译时,**ISO 8859**是ASCII标准的扩展 .

* 现在,Linux文件通常解释为**UTF-8**,**Unicode**的一种编码, 一套字符标准能够代表大量的语言.

* 对于东亚语言, **UTF-8 **字符是用**3 bytes**翻译的并且**UTF-16**字符是用**2 bytes**翻译的.对于西方语言(例如德语), **UTF-16**字符是用**2 bytes**翻译的,并且所有字符之前有**00**.

* 在**UTF-16**中,句子以不像其他任何部分文本编码的**fe ff**开始(小数为254 255) .这些是**Unicode byte order mark** (BOM),用来防范某些类型的编码错误[1].


* Linux字符集之间有一个命令翻译:

```
$ recode iso8859-1..utf-8
```

* 如果你看到**mojibake**,这是一个字符集编码不匹配错误,是有用的.


* 只有两个强制性规则的字符不能在文件名中出现:空字节(字节数值为0)和斜线 **/**.




----

# Extra Juice: (pseudo)-Random Tricks

## Creating Pseudo-Random Passwords

*向你的**~/.bashrc**添加如下内容:

```
genpass() {
    local p=$1
        [ "$p" == "" ] && p=16
        tr -dc A-Za-z0-9_ < /dev/urandom | head -c ${p} | xargs
}
```

* 接着,生成密码,只输入:

```
$ genpass
```

*例如:

```sh
$ genpass
dIBObynGX9epYogz
$ genpass 8
c_yhmaXt
$ genpass 12
FZI2wz2LzyVQ
$ genpass 14
ZEfgQvpY4ixePt
```


---
## Password Asterisks

*当您输入您的密码时,默认在终端看不到任何反馈. 如果相反你想看到星号,那么编辑:

```
$ sudo visudo
```

来获得权限:

```
Defaults                           pwfeedback
```


----
## imagemagick

* 你可以使用***imagemagick***在终端创建一个gif文件:

```
$ mogrify -resize 640x480 *.jpg
$ convert -delay 20 -loop 0 *.jpg myimage.gif
```

---
## 简单访问历史


* 输入```!!``` 运行历史上最后一条命令, ```!-2``` 以运行在此之前的指令以及其他.




