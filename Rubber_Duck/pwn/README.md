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

* 菜单或应用程序模拟应用程序键，有时被称为菜单键或上下文菜单键。在Windows系统上，这类似于F10键组合的变化。
  GUI d
  菜单
  字符串 v
  字符串 d

* 转变: 不同于大写锁定、巡航控制冷却，在导航字段选择文本和其他函数时，可以使用SHIFT命令。
  转变插入
  REM 这是大多数操作系统的粘贴

* ALT键在许多自动化操作中都有帮助:
  GUI r
  延迟 50
  字符串 notepad.exe
  输入
  延迟 100
  字符串 Hello World
  ALT f
  字符串 s
  REM alt-f 停文件菜单和保存。

* CONTROL or CTRL:
  CONTROL ESCAPE
  REM 这就相当于Windows中的GUI键

* 方向键: ^ 命令 ^ | 下箭头 或 下 | | 左箭头 或 左 | | 右箭头 或 右 | | 上箭头 或 上 |


编译
==========

鸭式脚本被编译成十六进制文件，准备命名为 inject.bin 然后移到 microSD 卡的根上，用USB橡皮鸭来执行。

这是利用 duckencoder 这个工具来完成的.

duckencoder 是一个跨平台的命令行Java程序，它将小鸭脚本语法转换成十六进制文件。

例如在Linux系统上:

java -jar duckencoder.jar -i exploit.txt -o /media/microsdcard/inject.bin


简单的鸭子有效负载产生器
=============================

也是一个不错的选择。
https://code.google.com/p/simple-ducky-payload-generator/downloads/list


维基
====
https://code.google.com/p/ducky-decode/wiki/Index?tm=6
