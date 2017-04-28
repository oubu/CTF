# Linux Hacking

## 提权

* [Unix Privilege Escalation Exploits by years](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack).

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

* To put a job (process) in the background we either run it with **&** or we press CTRL-Z and then type **bg**. To bring back to the foreground, we type **fg**.

* To get the list of running jobs in the shell, we type **jobs**. Each job has a **job ID** which can be used with the percent sign **%** to **bg**, **fg** or **kill** (described below).


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

or

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

* 为了向**stdout**正在运行的地方发送程序错误的信息，*i.e.*将其并入一个单独的字串流（这在导管输送中极为有效）:

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

    * A numeric form using octal modes: read = 4, write = 2, execute = 1, where you multiply by user = x100, group = x10, all = x1, and sum the values corresponding to the granted permissions. For example 755 = 700 + 50 + 5 = rwxr-xr-x: ``` $ chmod 774 <FILENAME>```

    * An abbreviated letter-based form using symbolic modes:  u, g, or a, followed by a plus or minus, followed by a letter r, w, or x. This means that u+x "grants user execute permission", g-w  "denies group write permission", and a+r  "grants all read permission":```$ chmod g-w <FILENAME>```.


* 你可以使用```chgrp```来改变组别,与改变权限是一样的逻辑.



* 如果想要在最近的文件夹里查看文件的权限，需要输入:

```
$ ls -l
```

* For example, ```-rw-r--r--``` means that it is a file (-) where the owner has read (r) and write (w) permissions, but not execute permission (-).


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

* 你可以立刻使用**diff3**来比较三个文件，其中一个被用以作为另外两个的参考依据.


### file

* 命令**file**展现了文件的真实属性:

```
$ file requirements.txt
requirements.txt: ASCII text
```

### grep
* **grep** finds matches for a particular search pattern. The flag **-l** lists the files that contain matches, the flag **-i** makes the search case insensitive, and the flag **-r** searches all the files in a directory and subdirectory**grep**寻找特定搜索模式匹配.:

```
$ grep -lir <PATTERN> <FILENAME>
```

* For example, to remove lines that are not equal to a word:

```
$ grep -xv <WORD> <FILENAME>
```

---
## Listing or Searching for Files


### ls

* **ls**  lists  directory and files. Useful flags are **-l** to list the permissions of each file in the directory and **-a** to include the dot-files:

```
$ ls -la
```

* To list files sorted by size:

```
$ ls -lrS
```

* To list the names of the 10 most recently modified files ending with .txt:

```
$ ls -rt *.txt | tail -10
```


### tree

* The **tree** command lists contents of directories in a tree-like format.


### find

* To find files in a directory:

```
$ find <DIRECTORY> -name <FILENAME>
```

### which

* To find  binaries in PATH variables:

```
$ which ls
```

### whereis

* To find any file in any directory:

```
$ whereis <FILENAME>
```

### locate

* To find files by name (using database):

```
$ locate <FILENAME>
```

* To test if a a file exist:

```
$ test -f <FILENAME>
```

---
## Modifying Files

### true

* To make a file empty:
```
$ true > <FILENAME>
```

### tr

*  **tr** takes a pair of strings as arguments and replaces, in its input, every letter that occurs in the first string by the corresponding characters in the second string. For example, to make everything lowercase:

```
$ tr A-Z a-z
```

* To put every word in a line by replacing spaces with newlines:

```
$ tr -s ' ' '\n'
```

* To combine multiple lines into a single line:


```
$ tr -d '\n'
```

* **tr** doesn't accept the names of files to act upon, so we can pipe it with cat to take input file arguments (same effect as ```$ <PROGRAM> < <FILENAME>```):

```
$ cat "$@" | tr
```

### sort

* Sort the contents of text files. The flag **-r** sort backwards, and the flag **-n** selects numeric sort order (for example, without it, 2 comes after 1000):

```
$ sort -rn <FILENAME>
```

* To output a frequency count (histogram):

```
$ sort <FILENAME> | uniq -c | sort -rn
```

* To chose random lines from a file:

```
$ sort -R  <FILENAME> | head -10
```

* To combine multiple files into one sorted file:

```
$ sort -m <FILENAME>
```

### uniq


* **uniq** remove *adjacent* duplicate lines. The flag **-c** can include a count:

```
$ uniq -c <FILENAME>
```

* To output only duplicate lines:

```
$ uniq -d <FILENAME>
```

### cut

* **cut** selects particular fields (columns) from a structured text files (or particular characters from each line of any text file). The flag **-d** specifies what delimiter should be used to divide columns (default is tab), the flag **-f** specifies which field or fields to print and in what order:

```
$ cut -d ' ' -f 2 <FILENAME>
```

* The flag **-c** specifies a range of characters to output, so **-c1-2** means to output only the first two characters of each line:

```
$ cut -c1-2 <FILENAME>
```

### join
* **join** combines multiple file by common delimited fields:

```
$ join <FILENAME1> <FILENAME2>
```




----
## Creating Files and Directories

### mkdir

* **mkdir** creates a directory. An useful flag is **-p** which creates  the entire path of directories (in case they don't exist):

```
$ mkdir -p <DIRNAME>
```


### cp

* Copying directory trees is done with **cp**. The flag **-a** is used to preserve all metadata:

```
$ cp -a <ORIGIN> <DEST>
```

* Interestingly, commands enclosed in **$()** can be run and then the output of the commands is substituted for the clause and can be used as a part of another command line:

```
$ cp $(ls -rt *.txt | tail -10) <DEST>
```


### pushd and popd

* The **pushd** command saves the current working directory in memory so it can be returned to at any time, optionally changing to a new directory:

```
 $ pushd ~/Desktop/
```

* The **popd** command returns to the path at the top of the directory stack.

### ln

* Files can be linked with different names with the **ln**. To create a symbolic (soft) link you can use the flag **-s**:

```
$ ln -s <TARGET> <LINKNAME>
```


### dd

* **dd** is used for disk-to-disk copies, being useful for making copies of raw disk space. For example, to back up your [Master Boot Record](http://en.wikipedia.org/wiki/Master_boot_record) (MBR):

```
$ dd if=/dev/sda of=sda.mbr bs=512 count=1
```

* To use **dd** to make a copy of one disk onto another:

```
$ dd if=/dev/sda of=/dev/sdb
```



----
## Network and Admin

### du

* **du** shows how much disk space is used for each file:

```
$ du -sha
```

* To see  this information sorted  and only the 10 largest files:

```
$ du -a | sort -rn | head -10
```

* To determine which subdirectories are taking a lot of disk space:

```
$ du --max-depth=1  | sort -k1 -rn
```

### df

* **df**  shows how much disk space is used on each mounted filesystem. It displays  five columns for each filesystem: the name, the size, how much is used, how much is available, percentage of use, and where it is mounted. Note the values won't add up because Unix filesystems have **reserved** storage blogs which only the root user can write to.

```
$ df -h
```



### ifconfig

* You can check and configure your network interface with:

```
$ ifconfig
```

* In general, you will see the following devices when you issue **ifconfig**:

    * ***eth0***: shows the Ethernet card with information such as: hardware (MAC) address, IP address, and the network mask.

    * ***lo***: loopback address or localhost.


* **ifconfig** is supposed to be deprecated. See [my short guide on ip-netns](https://coderwall.com/p/uf_44a).


### dhclient

* Linux has a DHCP server that runs a daemon called ```dhcpd```, assigning IP address to all the systems on the subnet (it also keeps logs files):

```
$ dhclient
```

### dig


* **dig** is a DNS lookup utility (similar to ```dnslookup``` in Windows).

### netstat


* **netstat** prints the network connections, routing tables, interface statistics, among others. Useful  flags are **-t** for TCP, **-u** for UDP, **-l** for listening, **-p** for program, **-n** for numeric. For example:

```
$ netstat -tulpn
```



### netcat, telnet and ssh

* To connect to a host server, you can  use **netcat** (nc) and **telnet**. To connect under an encrypted session, **ssh** is used. For example, to send a string to a host at port 3000:

```
$ echo 4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e | nc localhost 3000
```

* To telnet to localhost at port 3000:

```
$ telnet localhost 3000
```



### lsof

* **lsof** lists open files (remember that everything is considered a file in Linux):

```
$ lsof <STRING>
```

* To see open TCP ports:

```
$ lsof | grep TCP
```

* To see IPv4 port(s):

```
$ lsof -Pnl +M -i4
```

* To see IPv6 listing port(s):

```
$ lsof -Pnl +M -i6
```



---

## Useful Stuff

### echo


* **echo** prints its arguments as output. It can be useful for pipeling, and in this case you use the flag **-n** to not output the trailing new line:
```
$ echo -n <FILENAME>
```

* **echo** can be useful to generate commands inside scripts (remember the discussion about file descriptor):

```
$ echo 'Done!' >&2
```

* Or to find shell environment variables (remember the discussion about them):

```
$ echo $PATH
```

* Fir example, we can send the current date information to a file:

```
$ echo Completed at $(date) >> log.log
```

### bc

* A calculator program is given by the command **bc** The flag **-l** stands for the standard math library:

```
$ bc -l
```

* For example, we can make a quick calculation with:
```
$ echo '2*15454' | bc
30908
```



### w, who, finger, users


* To find information about logged users you can use the commands **w, who, finger**, and **users**.





---
## Regular Expression 101

* **Regular expressions** (regex) are  sequences of characters that forms a search pattern for use in pattern matching with strings.

* Letters and numbers match themselves. Therefore,  'awesome' is a regular expression that matches 'awesome'.

* The main rules that can be used with **grep** are:
    * ```.``` matches any character.
    * ```*``` any number of times (including zero).
    * ```.*``` matches any string (including empty).
    * ```[abc]``` matches any character a or b or c.
    * ```[^abc]``` matches any character other than a or b or c.
    * ```^``` matches the beginning of a line.
    * ```$``` matches the end of a line.

* For example, to find lines in a file that begin with a particular string you can use the regex symbol **^**:

```
$ grep ^awesome
```

* Additionally, to find lines that end with a particular string you can use **$**:

```
$ grep awesome$
```

*  As an extension, **egrep** uses a version called *extended regular expresses* (EREs) which include things such:
    * ```()``` for grouping
    * ```|``` for or
    * ```+``` for one or more times
    * ```\n``` for back-references (to refer to an additional copy of whatever was matched before by parenthesis group number n in this expression).

* For instance, you can use ``` egrep '.{12}'```to find words of at least 12 letters. You can use ```egrep -x '.{12}'``` to find words of exactly twelve letters.




---

## Awk and Sed

* **awk**  is a pattern scanning tool while **sed** is a stream editor for filtering and transform text. While these tools are extremely powerful, if you have knowledge of any very high level languages such as Python or Ruby, you  don't necessary need to learn them.

### sed

* Let's say we want  to replace every occurrence of *mysql* and with MySQL (Linux is case sensitive), and then save the new file to <FILENAME>. We can write an one-line command that says  "search for the word mysql and replace it with the word MySQL":

```
$ sed s/mysql/MySQL/g <FILEORIGIN> > <FILEDEST>
```

* To replace any instances of period followed by any number of spaces with a period followed by a single space in every file in this directory:

```
$ sed -i 's/\. */. /g' *
```

* To pass an input through a stream editor and then quit after printing the number of lines designated by the script's first parameter:

```
$ sed ${1}q
```




----

# Some More Advanced Stuff


## Scheduling Recurrent Processes


### at
* A very cute bash command is **at**, which allows you to run processes later (ended with CTRL+D):

```
$ at 3pm
```


### cron
* If you  have to run processes periodically, you should use **cron**, which is already running as a [system daemon](http://en.wikipedia.org/wiki/Daemon_%28computing%29). You can add a list of tasks in a file named **crontab** and install those lists using a program also called **crontab**. **cron** checks all the installed crontab files and run cron jobs.


* To view the contents of your crontab, run:

```
$ crontab -l
```

* To edit your crontab, run:

```
$ crontab -e
```

* The format of cron job is: *min, hour, day, month, dow* (day of the week, where Sunday is 0). They are separated by tabs or spaces. The symbol * means any. It's possible to specify many values with commas.

* For example, to run a backup every day at 5am, edit your crontab to:

```
0 5 * * * /home/files/backup.sh
```

* Or if you want to remember some birthday, you can edit your crontab to:

```
* * 16 1 * echo "Remember Mom's bday!"
```


---
##  rsync

*  **rsync**  performs file synchronization and file transfer. It can compress the data transferred using *zlib* and can use SSH or [stunnel](https://www.stunnel.org/index.html) to encrypt the transfer.

* **rsync** is very efficient when recursively copying one directory tree to another because only the differences are transmitted over the network.

* Useful flags are: **-e** to specify the SSH as remote shell, **-a** for archive mode, **-r** for recurse into directories, and **-z** to compress file data.

* A very common set is **-av** which makes **rsync** to work recursively, preserving metadata about the files it copies, and displaying the name of each file as it is copied. For example, the command below is used to transfer some directory  to the **/planning** subdirectory on a remote host:

```
$ rsync -av <DIRECTORY> <HOST>:/planning
```



----
## File Compression

* Historically, **tar** stood for tape archive and was used to archive files to a magnetic tape. Today **tar** is used to allow you to create or extract files from an archive file, often called a **tarball**.

* Additionally you can add *file compression*, which works by finding redundancies in a file (like repeated strings) and creating more concise representation of the file's content. The most common compression programs are **gzip** and **bzip2**.

* When issuing **tar**, the flag **f** must be the last option. No hyphen is needed. You can add **v** as verbose.

* A simple tarball is created with the flag **c**:

```
$ tar cf <FILE.tar> <CONTENTS>
```

* To extract a tarball you use the flag **x**:

```
$ tar xf <FILE.tar>
```

### gzip


* **gzip** is the most frequently used Linux compression utility. To create the archive and compress with gzip you use the flag **z**:

```
$ tar zcf <FILE.tar.gz>
```

* You can directly work with gzip-compressed files with ```zcat, zmore, zless, zgrep, zegrep```.

### bzip2

* **bzip2** produces files significantly smaller than those produced by gzip. To create the archive and compress with bz2 you use the flag **j**:

```
$ tar jcf <FILE.tar.bz2>
```

### xz

* **xz** is the most space efficient compression utility used in Linux. To create the archive and compress with xz:

```
$ tar Jcf <FILE.tar.xz>
```


----
## Logs

* Standard logging facility can be found  at ```/var/log```. For instance:
    *  ```/var/log/boot.log``` contains information that are logged when the system boots.
    * ```/var/log/auth.log``` contains system authorization information.
    * ```/var/log/dmesg``` contains kernel ring buffer information.


* The file ```/etc/rsyslog.conf``` controls what goes inside the log files.

* The folder ```/etc/services``` is a plain ASCII file providing a mapping between friendly textual names for internet services, and their underlying assigned port numbers and protocol types. To check it:

```
$ cat /etc/services
$ grep 110 /etc/services
```

* To see what your system is logging:

```
$ lastlog
```


-----
## /proc and inodes

* If the last link to a file is deleted but this file is open in some editor, we can still retrieve its content. This can be done, for example, by:
    1. attaching a debugger like **gdb** to the program that has the file open,

    2. commanding the program to read the content out of the file descriptor (the **/proc** filesystem), copying the file content directly out of the open file descriptor pseudo-file inside **/proc**.

* For example, if one runs ```$ dd if=/dev/zero of=trash & sleep 10; rm trash```, the available disk space on the system will continue to go downward (since more  contents gets written into the file by which **dd** is sending its output).

* However, the file can't be seen everywhere in the system! Only  killing the **dd** process will cause this space to be reclaimed.

* An **index node** (inode) is a data structure used to represent a filesystem object such as files or  directories. The true name of a file, even when it has no other name, is in fact its *inode number* within the filesystem it was created, which can be obtained by
```
$ stat
```
or
```
$ ls -i
```

* Creating a hard link with **ln** results in a new file with the same *inode number* as the original. Running *rm* won't affect the other file:

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

* A Linux text file contains lines consisting of zero of more text characters, followed by the **newline character** (ASCII 10, also referred to as hexadecimal 0x0A or '\n').

* A text with a single line containing the word 'Hello' in  ASCII would be 6 bytes (one for each letter, and one for the trailing newline). For example, the text below:

```
$ cat text.txt
Hello everyone!
Linux is really cool.
Let's learn more!
```

is represented as:

```
$ hexdump -c < text.txt
0000000   H   e   l   l   o       e   v   e   r   y   o   n   e   !  \n
0000010   L   i   n   u   x       i   s       r   e   a   l   l   y
0000020   c   o   o   l   .  \n   L   e   t   '   s       l   e   a   r
0000030   n       m   o   r   e   !  \n
0000038
```

* The numbers displayed at left are the hexadecimal byte offsets of each output line in the file.

* Unlike text files on other operating systems, Linux files does not end with a special end-of-file character.


* Linux text files were traditionally always interpreted as **ASCII**. In ASCII, each character is a single byte, the ASCII standard as such defines exactly **128 characters** from **ASCII 0 to ASCII 127**. Some of them are non-printable (such as newline). The printable stats at **32**. In that case, **ISO 8859** standards were  extensions to ASCII where the character positions **128 to 255** are given foreign-language interpretation.

* Nowadays, Linux files are most often interpreted as **UTF-8**, which is an encoding of **Unicode**, a character set standard able to represent a very large number of languages.

* For East asian languages, **UTF-8 **chars are interpreted with **3 bytes** and  **UTF-16** chars are interpreted with **2 bytes**. For western languages (such as German, for example), **UTF-16** characters are interpreted with **2 bytes**, and all the regular characters have **00** in front of it.

* In **UTF-16**, sentences start with two bytes **fe ff** (decimal 254 255) which don't encode as any part of the text. These are the **Unicode byte order mark** (BOM), which guards against certain kinds of encoding errors [1].


* Linux has a command to translate between character sets:

```
$ recode iso8859-1..utf-8
```

* This is useful if you see a **mojibake**, which is a character set encoding mismatch bug.


* There are only two mandatory rules about characters that can't appear in filename: null bytes (bytes that have numeric value zero) and forward slashes **/**.




----

# Extra Juice: (pseudo)-Random Tricks

## Creating Pseudo-Random Passwords

* Add this to your **~/.bashrc**:

```
genpass() {
    local p=$1
        [ "$p" == "" ] && p=16
        tr -dc A-Za-z0-9_ < /dev/urandom | head -c ${p} | xargs
}
```

* Then, to generate passwords, just type:

```
$ genpass
```

* For example:

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

* By default, when you type your password in the terminal you should see no feedback. If you would like to see asterisks instead, edit:

```
$ sudo visudo
```

to have the value:

```
Defaults                           pwfeedback
```


----
## imagemagick

* You can create a gif file from terminal with  ***imagemagick***:

```
$ mogrify -resize 640x480 *.jpg
$ convert -delay 20 -loop 0 *.jpg myimage.gif
```

---
## Easy access to the History


* Type ```!!``` to run the last command in the history, ```!-2``` for the command before that, and so on.




