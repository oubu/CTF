# 构建一个UDP端口扫描工具(by bt3)

当涉及侦察目标网络时，第一步无疑是发现主机。这个任务需要同时拥有嗅探和解析网络中的包的能力。

几个星期以前，我提到[如何使用Wireshark](http://bt3gl.github.io/wiresharking-for-fun-or-profit.html)来抓包，但是如果没有Wireshark可用来监听网络流量呢？

同样的，Python提供了几种解决方法，我今天将经过一些步骤来构建一个**UDP主机发现工具**。首先，我们将看到我们如何使用[原始套接字](http://en.wikipedia.org/wiki/Raw_socket)来写一个简单的嗅探器，可以用来观测并解码网络数据包。 to  write a simple sniffer, which is able to view and decode network packets.接下来，我们要在一个子网中多线程运行这个过程，这将形成我们的扫描仪。

关于**原始套接字**的一个很棒的事情就是他们允许底层的网络信息。比如说，我们可以使用它来检测IP和ICMP的头部，它们在OSI模型的第三层（网络层）。

使用**UDP数据报**的比较棒的事情是，和TCP不同，它们被向整个子网发送时不会带来很多开销(记住TCP的[握手](http://www.inetdaemon.com/tutorials/internet/tcp/3-way_handshake.shtml))。我们所需要做的就是等待ICMP的应答，主机是可到达的还是关闭的（不可到达的）。

----

##  写一个数据包的嗅探器

我们可以从一个简单的任务开始：使用python的[socket](http://bt3gl.github.io/black-hat-python-networking-the-socket-module.html)库，我们可以写一个很简单的数据包嗅探器。

在这个嗅探器中，我们创建一个原始套接字，然后将他与一个公共接口连接。这个接口应该为**混杂模式**，这意味着网卡所能看到的所有的包将被捕捉，即使它不是要发送到主机。

要记住的一个小细节是，当我们使用Windows的时候，会有些不同：这里我们需要向接口发送一个[IOCTL](http://en.wikipedia.org/wiki/Ioctl)包，来设置接口为**混杂模式**。另外，尽管Linux需要使用ICMP，Windows允许独立于协议来嗅探即将被接收的包。


```python
import socket
import os

# host to listen
HOST = '192.168.1.114'

def sniffing(host, win, socket_prot):
    while 1:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_prot)
        sniffer.bind((host, 0))

        # include the IP headers in the captured packets
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if win == 1:
            sniffer.ioctl(socket.SIO_RCVALL, socket_RCVALL_ON)

        # read in a single packet
        print sniffer.recvfrom(65565)

def main(host):
    OS = os.name
    if OS == 'nt':
        socket_prot = socket.IPPROTO_IP
        sniffing(host, 1, socket_prot)
    else:
        socket_prot = socket.IPPROTO_ICMP
        sniffing(host, 0, socket_prot)

if __name__ == '__main__':
    main(HOST)
```

为了测试这个脚本，我们可以在一个终端窗口中运行下面的命令：

```sh
$ sudo python sniffer.py
```

接着，在另一个窗口中，我们可以[ping](http://en.wikipedia.org/wiki/Ping_(networking_utility))或者[traceroute](http://en.wikipedia.org/wiki/Traceroute)一些地址，比如www.google.com。 结果大概像这样：

```sh
$ sudo python raw_socket.py
('E\x00\x00T\xb3\xec\x00\x005\x01\xe4\x13J}\xe1\x11\xc0\xa8\x01r\x00\x00v\xdfx\xa2\x00\x01sr\x98T\x00\x00\x00\x008\xe3\r\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567', ('74.125.225.17', 0))
('E\x00\x00T\xb4\x1b\x00\x005\x01\xe3\xe4J}\xe1\x11\xc0\xa8\x01r\x00\x00~\xd7x\xa2\x00\x02tr\x98T\x00\x00\x00\x00/\xea\r\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567', ('74.125.225.17', 0))
```

现在，非常显然我们需要解码这些头部信息。

----

## 解码IP和ICMP层

一个典型的IP头部有着这样的结构，所有的部分都属于一个变量（这个头部本来是[用C写的](http://minirighi.sourceforge.net/html/structip.html)):

![](http://i.imgur.com/3fmVLJS.jpg)


同样，ICMP头部的内容也不相同，但每个消息都有着相同的三个部分：**类型**和**编码** (告诉接收主机需要解码ICMP消息的类型)和**校验和**。

![](http://i.imgur.com/gsUPKRa.gif)


对于我们的嗅探器来说，我们在寻找**类型值为3t**和**编码值为3**的**不可到达的目的**和**端点**的[ICMP消息错误](http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages).


为了表示这个头部，我们使用python的[ctypes](https://docs.python.org/2/library/ctypes.html)库创建了一个类：

```python
import ctypes

class ICMP(ctypes.Structure):
    _fields_ = [
    ('type',        ctypes.c_ubyte),
    ('code',        ctypes.c_ubyte),
    ('checksum',    ctypes.c_ushort),
    ('unused',      ctypes.c_ushort),
    ('next_hop_mtu',ctypes.c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass
```

现在我们要开始写IP/ICMP头解码程序了。下面的这个脚本创建了一个嗅探器套接字（就像我们之前做的那样），然后它将执行一个循环连续地读入包并解码信息。 

注意对于IP头部来说，代码读入数据包，将前20个字节压缩到原始缓冲区，然后打印头部变量。ICMP的头部信息紧随其后：

```python
import socket
import os
import struct
import ctypes
from ICMPHeader import ICMP

# host to listen on
HOST = '192.168.1.114'

def main():
    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind(( HOST, 0 ))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while 1:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = raw_buffer[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

        # Create our IP structure
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        print 'IP -> Version:' + str(version) + ', Header Length:' + str(ihl) + \
        ', TTL:' + str(ttl) + ', Protocol:' + str(protocol) + ', Source:'\
         + str(s_addr) + ', Destination:' + str(d_addr)

        # Create our ICMP structure
        buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)

        print "ICMP -> Type:%d, Code:%d" %(icmp_header.type, icmp_header.code) + '\n'

if __name__ == '__main__':
    main()
```

在一个终端中运行这个脚本，然后在另一个终端中发送**ping**命令，会返回如下信息（注意ICMP类型值为0）：

```sh
$ ping www.google.com
PING www.google.com (74.125.226.16) 56(84) bytes of data.
64 bytes from lga15s42-in-f16.1e100.net (74.125.226.16): icmp_seq=1 ttl=56 time=15.7 ms
64 bytes from lga15s42-in-f16.1e100.net (74.125.226.16): icmp_seq=2 ttl=56 time=15.0 ms
(...)
```

```sh
$ sudo python ip_header_decode.py
IP -> Version:4, Header Length:5, TTL:56, Protocol:1, Source:74.125.226.16, Destination:192.168.1.114
ICMP -> Type:0, Code:0
IP -> Version:4, Header Length:5, TTL:56, Protocol:1, Source:74.125.226.16, Destination:192.168.1.114
ICMP -> Type:0, Code:0
(...)
```

另一方面，如果我们执行**traceroute**：

```sh
$ traceroute www.google.com
traceroute to www.google.com (74.125.226.50), 30 hops max, 60 byte packets
 1  * * *
 2  * * *
 3  67.59.255.137 (67.59.255.137)  17.183 ms 67.59.255.129 (67.59.255.129)  70.563 ms 67.59.255.137 (67.59.255.137)  21.480 ms
 4  451be075.cst.lightpath.net (65.19.99.117)  14.639 ms rtr102.wan.hcvlny.cv.net (65.19.99.205)  24.086 ms 451be075.cst.lightpath.net (65.19.107.117)  24.025 ms
 5  64.15.3.246 (64.15.3.246)  24.005 ms 64.15.0.218 (64.15.0.218)  23.961 ms 451be0c2.cst.lightpath.net (65.19.120.194)  23.935 ms
 6  72.14.215.203 (72.14.215.203)  23.872 ms  46.943 ms *
 7  216.239.50.141 (216.239.50.141)  48.906 ms  46.138 ms  46.122 ms
 8  209.85.245.179 (209.85.245.179)  46.108 ms  46.095 ms  46.074 ms
 9  lga15s43-in-f18.1e100.net (74.125.226.50)  45.997 ms  19.507 ms  16.607 ms

```
我们会得到如下结果（注意ICMP的应答有多种类型):

```sh
sudo python ip_header_decode.py
IP -> Version:4, Header Length:5, TTL:252, Protocol:1, Source:65.19.99.117, Destination:192.168.1.114
ICMP -> Type:11, Code:0
(...)
IP -> Version:4, Header Length:5, TTL:250, Protocol:1, Source:72.14.215.203, Destination:192.168.1.114
ICMP -> Type:11, Code:0
IP -> Version:4, Header Length:5, TTL:56, Protocol:1, Source:74.125.226.50, Destination:192.168.1.114
ICMP -> Type:3, Code:3
IP -> Version:4, Header Length:5, TTL:249, Protocol:1, Source:216.239.50.141, Destination:192.168.1.114
ICMP -> Type:11, Code:0
(...)
IP -> Version:4, Header Length:5, TTL:56, Protocol:1, Source:74.125.226.50, Destination:192.168.1.114
ICMP -> Type:3, Code:3
```




------
## 写一个扫描程序

### netaddr

我们现在来写全扫描程序。首先，让我们安装[netaddr](https://pypi.python.org/pypi/netaddr)。这个库允许我们使用像192.168.1.0/24这样的子网掩码：

```sh
$ sudo pip install netaddr
```

我们可以使用下面这个小代码片测试这个库（它应该会输出“OK”）：

```python
import netaddr

ip = '192.168.1.114'
if ip in netaddr.IPNetwork('192.168.1.0/24'):
    print('OK!')
```

### 写扫描程序

为了写扫描程序我们将集合我们所有的东西，然后添加一个循环将带有一个字符特征码的UDP数据报广播到目标子网中的所有地址。

为了执行这样的过程，每个包将会分别从不同的线程中被发送，以确保不被其他的嗅探应答干扰：

```python
import threading
import time
import socket
import os
import struct
from netaddr import IPNetwork, IPAddress
from ICMPHeader import ICMP
import ctypes

# host to listen on
HOST = '192.168.1.114'
# subnet to target (iterates through all IP address in this subnet)
SUBNET = '192.168.1.0/24'
# string signature
MESSAGE = 'hellooooo'

# sprays out the udp datagram
def udp_sender(SUBNET, MESSAGE):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in IPNetwork(SUBNET):
        try:
            sender.sendto(MESSAGE, ("%s" % ip, 65212))
        except:
            pass

def main():
    t = threading.Thread(target=udp_sender, args=(SUBNET, MESSAGE))
    t.start()

    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind(( HOST, 0 ))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # continually read in packets and parse their information
    while 1:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = raw_buffer[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

        # Create our IP structure
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        src_addr = socket.inet_ntoa(iph[8]);

        # Create our ICMP structure
        buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)

        # check for the type 3 and code and within our target subnet
        if icmp_header.code == 3 and icmp_header.type == 3:
            if IPAddress(src_addr) in IPNetwork(SUBNET):
                if raw_buffer[len(raw_buffer) - len(MESSAGE):] == MESSAGE:
                    print("Host up: %s" % src_addr)

if __name__ == '__main__':
    main()
```

最后运行这个扫描程序，将会得到类似下面这样的结果：

```sh
$ sudo python scanner.py
Host up: 192.168.1.114
(...)
```

非常简洁！

顺便说一下，我们扫描的结果可以和你的路由器中的**DHCP表**中的IP地址值进行校验。它们应该是匹配的！They should match!

