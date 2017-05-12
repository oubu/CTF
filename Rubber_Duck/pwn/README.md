有效载荷
============

在PowerShell脚本编写(只针对安装了PowerShell的工作目标机器,例如Windows 7/8,Windows Server 2008。还需要管理访问权限。


有效载荷来自三个类别:

* 侦察(报告由与目标计算机有关的信息生成):

计算机信息
用户信息
USB信息
共享驱动器的信息
程序信息
安装更新
用户文档列表
基本网络信息
网络扫描
端口扫描
无线配置文件副本
把屏幕截图
FireFox配置文件副本
提取SAM文件


* 开发
找到和上传文件(FTP)
禁用防火墙
添加用户
打开防火墙端口
启动无线接入点
分享C:\开车
使RDP
创建一个反向Shell
本地DNS中毒
删除Windows更新


* 报告(总是连同上面的项目):
将报告保存到目标机
外部主机的FTP报告
电子邮件报告到GMAIL帐户
将文件保存到USB驱动器

我们将在有效载荷中使用最后一个。

请注意，我们使用QUACK作为u盘的名字。



极好的语法
============

* 每个命令都位于一条新行中

* 命令都是大写的

* 以REM开始的行不会被处理。

* DEFAULT_DELAY 或 DEFAULTDELAY 用于定义在每个后续命令序列之间等待多长时间(以毫秒为单位* 10)。
  DEFAULT_DELAY *必须在小鸭脚本的开头发行，并且是可选择的。
  DEFAULT_DELAY 100
  在随后的命令序列之间，REM延迟了100ms

* 延迟在鸭子的脚本中造成短暂的停顿
  延迟 500
  REM会等500毫秒，然后再继续下一个命令。

* 字符串处理文本后，对自动移位进行特殊处理。
  GUI r
  延迟500毫秒
  STRING notepad.exe
  输入
  延迟1000
  字符串Hello World！

* 窗户或GUI模拟Windows-Key:
  GUI r
  REM 将会持有 Windows-key 并按 r

* MENU or APP emulates the App key, sometimes referred to as the menu key or context menu key. On Windows systems this is similar to the SHIFT F10 key combo.
  GUI d
  MENU
  STRING v
  STRING d

* SHIFT: unlike CAPSLOCK, cruise control for cool, the SHIFT command can be used when navigating fields to select text, among other functions.
  SHIFT INSERT
  REM this is paste for most operating systems

* ALT key is instrumental in many automation operations:
  GUI r
  DELAY 50
  STRING notepad.exe
  ENTER
  DELAY 100
  STRING Hello World
  ALT f
  STRING s
  REM alt-f pulls up the File menu and s saves.

* CONTROL or CTRL:
  CONTROL ESCAPE
  REM this is equivalent to the GUI key in Windows

* Arrow Keys: ^ Command ^ | DOWNARROW or DOWN | | LEFTARROW or LEFT | | RIGHTARROW or RIGHT | | UPARROW or UP |


Compiling
==========

Ducky Scripts are compiled into hex files ready to be named inject.bin and moved to the root of a microSD card for execution by the USB Rubber Ducky.

This is done with the tool duckencoder.

duckencoder is a cross-platform command-line Java program which converts the Ducky Script syntax into hex files.

For example on a Linux system:

java -jar duckencoder.jar -i exploit.txt -o /media/microsdcard/inject.bin


Simple Ducky Payload Generator
=============================

Also a good option.
https://code.google.com/p/simple-ducky-payload-generator/downloads/list


Wiki
====
https://code.google.com/p/ducky-decode/wiki/Index?tm=6
