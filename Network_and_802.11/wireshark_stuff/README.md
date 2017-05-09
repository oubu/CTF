# [Wireshark指南(by bt3)](http://bt3gl.github.io/wiresharking-for-fun-or-profit.html)


[Wireshark](https://www.wireshark.org/)是一个开源的**网络封包分析**软件，允许实时流量分析并支持多种协议。

Wireshark也允许**网络取证**，对CTF比赛非常有用，比如说(看我的writeup，[D-CTF Quals 2014](http://bt3gl.github.io/exploring-d-ctf-quals-2014s-exploits.html)，CSAW Quals 2014 在 [Networking](http://bt3gl.github.io/csaw-ctf-2014-networking-100-big-data.html) 和 [Forensics](http://bt3gl.github.io/csaw-ctf-2014-forensics-200-why-not-sftp.html)).



------------------------------------------------------
# 网络架构

在我们理解并分析网络流量包之前，我们必须理解网络栈是如何工作的。


## OSI模型

[开放系统互联](http://en.wikipedia.org/wiki/OSI_model) (OSI)模型于1983年发布，是一种概念模型，通过将通信系统内部功能划分为抽象层来表示和标准化内部功能层。

![](http://i.imgur.com/dZyiOTX.png)

协议根据自身功能分离，层次结构使网络通信更加易于理解：



### 第1层: 物理层

表示传输网络数据的物理和电路媒介。

它包括了所有的硬件，集线器，网络适配器，电缆。

### 第2层: 数据链路层

提供了通过物理网络*传输数据*的方法。网桥和交换机是这一层的物理设备。

它负责提供可用于识别物理设备的寻址方案：[MAC地址](http://en.wikipedia.org/wiki/MAC_address)。

举例来说，这一层的协议有：[Ethernet](http://en.wikipedia.org/wiki/Ethernet)，[Token Ring](http://en.wikipedia.org/wiki/Token_ring)，[AppleTalk](http://en.wikipedia.org/wiki/AppleTalk)，和[Fiber Distributed Data Interface](http://en.wikipedia.org/wiki/Fiber_Distributed_Data_Interface) (FDDI)。

### 第3层: 网络层

它负责在物理网络之间路由数据，分配网络主机的*逻辑寻址*。它也负责处理*数据包碎片*和*错误检测*。

路由器和*路由表*属于这一层。这一层的协议有，比如：[Internet Protocol](http://en.wikipedia.org/wiki/Internet_Protocol) (IP)，[Internetwork Packet Exchange](http://en.wikipedia.org/wiki/Internetwork_Packet_Exchange)，和[Internet Control Message Protocol](http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) (ICMP)。


### 第4层: 传输层

提供两个主机之间的数据流量控制。许多防火墙和配置协议都在这一层工作。

这一层的协议有，比如：[UDP](http://en.wikipedia.org/wiki/User_Datagram_Protocol)和[TCP](http://en.wikipedia.org/wiki/Transmission_Control_Protocol)。

### 第5层: 会话层
负责两台计算机之间的*会话*，管理诸如正常终止连接的操作。它还可以确定连接是[双工或半双工](http://en.wikipedia.org/wiki/Duplex_%28telecommunications%29)。

这一层的协议有，比如：[NetBIOS](http://en.wikipedia.org/wiki/NetBIOS)和[NWLink](http://en.wikipedia.org/wiki/NWLink)。

### 第6层: 表示层

将接受的数据转换为应用层可以读取的格式，例如编码/解码和几种用于保护数据的加密/解密形式。

这一层的协议有，比如：[ASCII](http://en.wikipedia.org/wiki/ASCII)，[MPEG](http://en.wikipedia.org/wiki/Moving_Picture_Experts_Group)，[JPEG](http://en.wikipedia.org/wiki/JPEG)，和[MIDI](http://en.wikipedia.org/wiki/MIDI).

### 第7层: 应用层

为最终用户提供访问网络资源的详细信息。

这一层的协议有，比如：[HTTP](http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)，[SMTP](http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)，[FTP](http://en.wikipedia.org/wiki/File_Transfer_Protocol)，和[Telnet](http://en.wikipedia.org/wiki/Telnet).

---

## 数据封装

OSI模型不同层上的协议通过*数据封装*的方式，堆栈中的每个层都向报文添加一个头或者尾。

封装协议创建了一个[协议数据单元](http://en.wikipedia.org/wiki/Protocol_data_unit) (PDU)，包括添加了头和尾信息的数据。我们所说的*包*是完整的协议数据单元。

例如，在Wireshark中，我们可以跟踪更高层的PDU启动和停止的序列号。这允许我们测量传输PDU所需的时间(*显示过滤器*是**tcp.pdu.time**)。


---


## 交换机和路由器
捕获来自在**交换**网络上的目标设备的流量主要有四种方法：使用**集线器**，使用**tap**,通过端口镜像，或者通过ARP欺骗/缓存投毒。前两个方法显然需要一个集线器或者一个tap。端口镜像需要交换机的转发功能。参考资料[1]借鉴了一种决定使用哪种方法的比较好的途径：

![](http://i.imgur.com/aRUfmsp.png)


所有用于交换网络的技术也可以在**路由**网络中使用。但是，对于路由器，嗅探器的放置位置显得更加重要，因为设备的广播域仅在到达路由器之前扩展。

---
## 数据包的类型

在网络中有三种类型的数据包：

* **广播包**: 发送到网段上的所有端口。广播MAC地址是*ff:ff:ff:ff:ff:ff*（第二层）或者可能性最大的IP地址（第三层）。

* **组播包**: 从单源发送到多个目的端，以简化并尽可能少地使用带宽。

* **单播包**: 从一个端系统到另一个。


---
## 各层通用协议

### 地址解析协议（ARP） (第2层)

**逻辑地址**和**物理地址**都用于网络通信。逻辑地址用于多个网络（间接连接的设备）之间的通信。物理地址用于单个网络（如使用交换机彼此连接的设备）之间的通信。


[ARP](http://en.wikipedia.org/wiki/Address_Resolution_Protocol)是用于确定[MAC地址](http://en.wikipedia.org/wiki/MAC_address) (如物理地址为00:09:5B:01:02:03，属于第2层)对应一个特定的IP地址（如逻辑地址为10.100.20.1，属于第3层）的协议。

ARP解析过程使用两个包（*ARP请求*和*ARP响应*）来查找匹配的MAC地址，向域中的每个设备发送一个**广播包**，等待正确的客户端的响应。这样做是基于交换机使用一个MAC表来确定向哪个端口发送流量。

在Wireshark中，用这样的语句可以很容易获得ARP：**"Who has 192.168.11/ Tell 192.168.1.1"**。另外，你可以使用这种方法查询你的设备的ARP表：

```
$ arp -a
```

### Internet协议(第3层)

互联网上的每个接口必须拥有唯一的网络地址。Internet协议基于分组报头中的IP地址，在主机之间传递分组。

[IPv4](http://en.wikipedia.org/wiki/IPv4)地址是用于唯一标识网络中连接的设备的32位地址。它们由4组8个bit的，使用点分十进制表示法表示0~255之间十进制数。

此外，IP地址由两部分组成：**网络地址**和**主机地址**。网络地址表示*局域网*（LAN），主机地址标识该网络中的设备。

这两个部分的确定由另一组寻址信息给出，即**网络掩码**（网络掩码或子网掩码），也是32位长。子网掩码中，标识为1的位属于IP地址中的网络号，剩余位标识了主机号：

![](http://i.imgur.com/a7Evq9z.png)

此外，IP包头包含以下信息：

* **版本号**: 使用的IP版本

* **头长度**: IP头部长度

* **服务类型**: 路由器使用的优先处理流量的标识

* **总长度**: 包含IP头部的数据报的总长度

* **标识位**: 标识包或者分段分组序列

* **分段偏移**: 识别分组是否是段

* **生存时间**: 定义数据包的生命周期，计算通过路由器的速度（跳数/秒）。当一个数据包被创建时，会定义一个TTL，每当数据包被路由器转发是，TTL会减一。

* **协议**: 识别序列中下一个数据包的类型

* **头部校验和**: 错误侦测机制

* **源IP地址**.

* **目的IP地址**.

* **选项**: 路由和时间戳

* **数据**.



### 互联网控制信息协议（ICMP） (第3层)

ICMP是TCP/IP的一个效用协议，负责提供有关设备，服务，或网络上的路由的可用性信息。

使用ICMP的服务有，如：**ping**:

```
$ ping www.google.com
PING www.google.com (74.125.228.210) 56(84) bytes of data.
64 bytes from iad23s23-in-f18.1e100.net (74.125.228.210): icmp_seq=1 ttl=53 time=21.5 ms
64 bytes from iad23s23-in-f18.1e100.net (74.125.228.210): icmp_seq=2 ttl=53 time=22.5 ms
64 bytes from iad23s23-in-f18.1e100.net (74.125.228.210): icmp_seq=3 ttl=53 time=21.4 ms
```


还有**traceroute** (Windows发送ICMP数据包，Linux发送UDP):

```
$ traceroute www.google.com
traceroute to www.google.com (173.194.46.84), 30 hops max, 60 byte packets
 1  * * *
 2  67.59.254.85 (67.59.254.85)  30.078 ms  30.452 ms  30.766 ms
 3  67.59.255.137 (67.59.255.137)  33.889 ms 67.59.255.129 (67.59.255.129)  33.426 ms 67.59.255.137 (67.59.255.137)  34.007 ms
 4  rtr101.wan.hcvlny.cv.net (65.19.107.109)  34.004 ms 451be075.cst.lightpath.net (65.19.107.117)  32.743 ms rtr102.wan.hcvlny.cv.net (65.19.107.125)  33.951 ms
 5  64.15.3.222 (64.15.3.222)  34.972 ms 64.15.0.218 (64.15.0.218)  35.187 ms  35.120 ms
 6  * 72.14.215.203 (72.14.215.203)  29.225 ms  29.646 ms
 7  209.85.248.242 (209.85.248.242)  29.361 ms 209.85.245.116 (209.85.245.116)  39.780 ms  42.108 ms
 8  209.85.249.212 (209.85.249.212)  33.220 ms 209.85.252.242 (209.85.252.242)  33.500 ms  33.786 ms
 9  216.239.50.248 (216.239.50.248)  53.231 ms  57.314 ms 216.239.46.215 (216.239.46.215)  52.140 ms
10  216.239.50.237 (216.239.50.237)  52.022 ms 209.85.254.241 (209.85.254.241)  48.517 ms  48.075 ms
11  209.85.243.55 (209.85.243.55)  56.220 ms  45.359 ms  44.934 ms
12  ord08s11-in-f20.1e100.net (173.194.46.84)  43.184 ms  39.770 ms  45.095 ms
```

traceroute的工作方式是通过发送IP头中有特定功能的回显请求：**the TTL is 1**。这意味着数据包在第一跳后被丢弃。第二个数据包经过第一跳，在第二跳被丢弃(TTL is 2)，依此类推。

为了进行这个工作，路由器用*double-headed packet*来回复响应，包含IP头的副本和在原始回显请求中发送的数据。

PS: 看这篇Julia Evans的文章，学习如何创建一个简单的[*在15行代码内使用python的scapy实现的Traceroute*](http://jvns.ca/blog/2013/10/31/day-20-scapy-and-traceroute/).


### 传输控制协议(第4层)

通过**三次握手**在两个主机之间提供可靠的数据流。目的是使发送主机能够确保目的主机已经启动，并且让发送主机能够检查端口的可用性。

握手是这样进行的：

1. 主机A发送初始的无数据包，发送SYN标识和初始同步序列编号以及双方交互的[最大段长度](http://en.wikipedia.org/wiki/Maximum_segment_size) (MSS)。
2. 主机B返回一个SYN请求和ACK确认标识，及它的初始序列编号。
3. 主机A发送(ACK)确认包。

当通信完成之后，**TCP teardown**进程将开始运行，正常地结束两个设备间的连接。这个过程包含4个包：
1. 主机A发送有FIN+ACK标识的包。
2. 主机B发送一个ACK确认包，再发送一个FIN/ACK包。
4. 主机A发送ACK确认包。


但有时，连接可能会突然终端（比如由于潜在的攻击者发出端口扫描或者由于一个错误配置的主机）。在这些情况下，TCP使用RST标识重置数据包。这表明一个连接突然被关闭了或者连接请求被拒绝了。

还有，在使用TCP协议通信的时候，有65,535个端口可供使用，我们经常把他们分成两组：

* **标准端口**: 1到1023，提供给特定服务使用

* **临时端口**: 1024到65535，由服务随机选择。

最后，TCP头部包含以下信息：

* **源端口**.
* **目的端口**.
* **序列号**: 标识TCP报文段
* **确认号**: 另一个设备返回的包的序列号
* **Flags**: URG, ACK, PSH, RST, SYN, FIN标识，确认正在传输的TCP包的类型
* **窗口大小**: TCP收到的数据包的大小（字节为单位）
* **校验**: 确保TCP头部信息有效性
* **紧急数据点**: CPU应当读取的包中的附加指示信息
* **选项**: 可选字段


### 用户数据报协议(第4层)

TCP被设计用于可靠的数据传输，UDP专注于速度。UDP从一个主机向另一个主机发送**数据报**的数据包，但不保证它们到达另一端。

与TCP不同，UDP不正式建立和终止主机之间的连接。因此，它通常依赖于内置的可靠性服务（如DNS和DHCP等协议）。

UDP报头的字段比TCP少：

* **源端口**.
* **目的端口**.
* **包长度**.
* **确认号**.


###  动态主机配置协议 (第7层)

In the beginning of the Internet, when a device needed to communicate over a network, it would be assigned an address by hand.

As the Internet grown, the **Bootstrap Protocol** (BOOTP) was created,   automatically assigning addresses to  devices. Later, BOOTP was replaced by DHCP.


### The Hypertext Transfer Protocol (Layer 7)

HTTP is the mechanism that allows browsers to connect to web servers to view web pages.  HTTP packets are built on the top of TCP and they are identified by one of the eight different request methods.


------------------------------------------------------


#  Analyzing Packets in Wireshark

In Wireshark, the entire process of network sniffing can be divided into three steps:

1.  **Collection**:   transferring the selected network interface into promiscuous mode so it can capture raw binary data.

2.  **Conversion**:  chunks of collected binary are converted into readable form.

3. **Analysis**: processing of the protocol type, communication channel, port number, protocol headers, etc.

## Collecting Packets
Network traffic sniffing is only possible if the ** network interface** (NIC) is transfered to **promiscuous mode**. This allows the transfer of all received traffic  to the CPU (instead of processing frames that the interface was intended to receive). If the NIC is not set to promiscuous mode, packets that are not destined to that controller are discarded.

##  Wireshark main's GUI
The Wireshark main's GUI is composed of four parts:

* **Capture's options**.
* **Packet List**: list all packets in the capture file. It can be edited to display packet number, relative time, source, destination, protocol, etc.
* **Packet details**: hierarchal display of information about a single packet.
* **Packet Bytes**: a packet in its raw, unprocessed form.

To start capturing packets, all you need to do is to choose the network interface. You may also edit a *capture filter* prior to the packet collection.



## Color Scheme

The packet list panel displays  several type of traffic by (configurable) colors. For instance:

* green is TCP (and consequently HTTP),
* dark blue is DNS,
* light blue is UDP,
* light yellow is for ARP,
* black identifies TCP packets with problems.

##  Packet Visualization and Statistics

Wireshark has several tools to learn about packets and networks:

* **Statistics -> IO Graphs**: Allows to graph throughput of data. For instance, you can use graphs to find peaks in the data, discover performance bottlenecks in individual protocols, and compare data streams. Filtering is available in this interface (for example, to show ARP and DHCP traffic).

* **Statistics -> TCP -> Stream Graph -> Round Trip Time Graph**:  Allows to  plot **round-trip times** (RTT) for a given capture file. This is the time it takes for an acknowledgment to be received from a sent packet.

* **Statistics -> Flow Graph**: Timeline-based representation of communication statistics (based on time intervals). It allows the visualization of connections and the flow of data over time.  A flow graph contains a column-based view of a connection between hosts and organizes the traffic. This analysis can show slow points or bottlenecks and determine if there is any latency.

* **Statistics -> Summary**: Returns a report about the entire process by features such as interface, capture duration and number, and size of packets.

* **Statistics -> Protocol Hierarchy**: Shows statistical information of different protocols  in a *nodal form*.  It arranges the protocols according to its layers, presenting them in percentage form. For example, if you know that your network usually gets 15%  ARP traffic, if you see a value such as 50%, you know something is wrong.

* **Statistics -> Conversations**: Shows the address of the endpoints involved in the conversation.

* **Statistics -> Endpoints**: Similar to conversations, reflecting the statistics of traffic to and from an IP address. For example, for TCP, it can look like  **SYN, SYN/ACK, SYN**.

* **Edit-> Finding Packet or CTRL-F**: Finds packets that match to some criteria. There are three options:
    * *Display filter*:  expression-based filter (for example **not ip**, **ip addr==192.168.0.10**,  or **arp**).
    * *Hex value*: packets with a hexadecimal (for example 00:ff, ff:ff).
    * *String*:  packets with a text string (for example admin or workstation).

* **Right click -> Follow TCP Stream**: Reassembles TCP streams into an  readable format (instead of having the data being in small chunks). The text displayed in *red* to signifies traffic from the source to the destination, and in  *blue* identifies traffic in the opposite direction. If you know the stream number (value to be followed to get various data packets), you can also use the following filter for the same purpose:

```
tcp.stream eq <number>
```

* **Right click -> Mark Packet or CTRL+M**: Helps to organization of relevant packets.




---
##  Filters

### The Berkeley Packet Filter Syntax
Wireshark's filtering is a very powerful feature. It uses the [Berkeley Packet Filter](http://en.wikipedia.org/wiki/Berkeley_Packet_Filter) (BFP) syntax.  The syntax corresponds to an **expression** which is made of one more **primitives**. These primitives can have  one or more **qualifier**, which are defined below:

* **Type**:  ID name or number (for example: **host**, **net**, **port**).
* **Dir**: transfer direction to or from the ID name or number (for example: **src** and **dst**).
* **Proto**: restricts the match to a particular protocol (for example: **ether**, **ip**, **tcp**, **udp**, or **http**)

A example of primitive is:
```
dst host 192.168.0.10
```
where **dst host** is the qualifier, and the IP address is the ID.

### Types of Filters
Packages can be filtering in two ways:

* **Capture filters**: specified when packets are being captured. This method is good for performance of large captures.
* **Display filters**: applied to an existing set of collected packets. This method gives more versatility since you have the entire data available.

In the following sessions I  show several examples of capture and display  filters.

### Capture Filters by Host Address and Name

* Traffic associated with a host's IPV4 address (also works for a IPv6 network).

```
host 172.16.16.150
```

* Traffic to or from a range of IP addresses:

```
net 192.168.0.0/24
```

* Device's hostname with the host qualifier:

```
host testserver
```

* If you are concerned that the IP address for a host changed, you can filter based on MAC address:

```
ether host ff-ff-ff-ff-ff-aa
```

* Only traffic coming from a particular host (host is an optional qualifier):

```
src host 172.16.16.150
```

* All the traffic leaving a host:

```
dst host 172.16.16.150
```

* Only  traffic to or from IP address 173.15.2.1

```
host 173.15.2.1
```

* Traffic from a range of IP addresses:

```
src net 192.168.0.0/24
```


### Capture Filters by Ports

* Only traffic on port 8000:

```
port 8000
```

* All traffic except on port 443:

```
!port 443
```

* Traffic going to a host listening on 80:

```
dst port 80
```

* Traffic within a range of port:

```
tcp portrange 1501-1549
```

* Both inbound and outbound traffic on port 80 and 21:

```
port 80 || port == 21
```

* Only non-http and non-SMTP traffic (equivalent):

```
host www.example.com and not (port 80 or port 25)
```

### Capture Filters by  Protocols

* Capture only unicast traffic (useful to get rid of noise on the network):

```
not broadcast and not multicast
```

*  ICMP traffic only:

```
icmp
```


* Drop ARP packets:

```
!arp
```

* Drop IPv6 traffic:

```
!ipv6
```

* DNS traffic:

```
dns
```

* Clear text email traffic:

```
smtp || pop || imap
```

### Capture Filters  by Packet's  Properties

* TCP packets with SYN flag set:

```
tcp[13]&2==2
```

* ICMP packets with destination unreachable (type 3):

```
icmp[0]==3
```

*  HTTP GET requests (bytes 'G','E','T' are hex values 47, 45, 54):

```
port 80 and tcp[((tcp[12:1] & 0xf0 ) >> 2  ):4 ] = 0x47455420
```

---
### Display Filters by Host Address and Name


* Filter by IP address:

```
ip.addr == 10.0.0.1
```

* IP source address field:

```
ip.src == 192.168.1.114
```

* IP address src/dst for a network range:

```
ip.addr== 192.168.1.0/24
```

### Display Filters by Ports

* Any TCP packet with 4000 as a source or destination port:

```
tcp.port == 4000
```

* Source port:

```
tcp.srcport == 31337
```

### Display Filters by  Protocols

* Drops  arp, icmp, dns, or whatever other protocols may be background noise:

```
!(arp or icmp or dns)
```

* Displays all re-transmissions in the trace (helps when tracking down slow application performance and packet loss):

```
tcp.analysis.retransmission
```

* ICMP Type field to find all PING packets:

```
icmp.type== 8
```

### Display Filters  by Packet's  Properties

* Displays all HTTP GET requests:

```
http.request
```

* Display all POST requests:

```
http.request.method == "POST"
```

* Filter for the HEX values:

```
udp contains 33:27:58
```

* Sequence number field in a TCP header:

```
tcp.seq == 52703261
```


* Packets that are less than 128 bytes in length:

```
frame.len <= 128
```

* TCP packets with SYN flag set:

```
tcp.flags.syn == 1
```

* TCP packets with RST flag set:

```
tcp.flags.rst == 1
```

* Displays all TCP resets:

```
tcp.flags.reset == 1
```

* IP flags where fragment bit is not set (see if someone is trying ping):

```
ip.flags.df == 0
```


--------------------------------------
#  Using Wireshak for Security


## Some Reconnaissance Tips

### Network Scan with SYN

A  TCP SYN scan is fast and reliable  method to scan ports and services in a network. It is also less noisy than other scanning techniques.

Basically, it relies on the three-way handshake process to determine which ports are open on a target host:

1. The attacker sends a TCP SYN packet to a range of ports on the victim.

2. Once this packet is received by the victim, the follow response will be observed:

    * **Open ports**: replies with a TCP SYN/ACK packet (three times). Then the attacker knows that port is open and a service is listening on it.

    * **Closed ports, not filtered**: the attacker receives a RST response.

    * **Filtered ports** (by a firewall, for example): the attacker does not receive any response.


### Operating System Fingerprint

Technique to determine the operating system on a system without have access to it.

In a **Passive Fingerprinting**, an attacker can use certain fields within packets sent from the target to craft a stealthy fingerprinting.

This is possible due the lack of specificity by protocol's [RFCs](http://en.wikipedia.org/wiki/Request_for_Comments): although the various fields contained in the TCP, UDP and IP headers are very specific, no default values are defined for these fields.

For instance, the following header values can help one to distinguish between several operating systems:

* **IP, Initial Time to Live**:
    - 64 for Linux, Mac OS
    - 128 for Windows
    - 255 for Cisco IOS
* **IP, Don't Fragment Flag**:
    - Set for Linux, Mac OS, Windows
    - Not set for Cisco IOS
* **TCP, Max Segment Size**:
    - 1440 for Windows
    - 1460 for Mac OS 10, Linux
* **TCP, Window Size**:
    - 2920-5840 for Linux
    - 4128 for Cisco  IOS
    - 65535 for for Mac OS 10
    - variable for Windows
* **TCP, StackOK**:
    - Set for Linux, Windowns
    - Not set for Cisco IOS, Mac OS 10

Note: A nice tool using operating system fingerprinting techniques is [p0f](http://lcamtuf.coredump.cx/p0f3/).



In **Active Fingerprinting**, the attacker actively sends crafted packets to the victim whose replies reveal the OS. This can be done with [Nmap](http://nmap.org/).

---


## Some Forensics Tips

### DNS Queries

Look at different DNS queries that are made while the user was online. A possible filter is:

```
dsn
```
This will give a view of any malicious DNS request done without the knowledge of the user. An example is a case where a  visited website has a hidden **iframe** with some malicious script inside.

### HTTP GET Headers

Look for different HTTP streams that have flown during the network activity:  HTML, JavaScript,  image traffic, 302 redirections, non-HTTP streams, Java Archive downloads, etc. A possible filter is:

```
http
```
You can also look at different GET requests  with:

```
tcp contains "GET"
```

### Checking for DNS Leaks with VMs

In a virtual machine look at **statistics --> Endponts**. There should be only one public IP address: the VPN server that the virtual machine is connected to.

---
## ARP Cache Poisoning

### Sniffing

ARP cache poisoning  allows tapping into the wire with Wireshark. This can be used for good or for evil.

The way this works is the following: all devices on a network communicate with each other on layer 3 using IP addresses. Because switches operate on layer 2 they only see MAC addresses, which are usually cached.

When a MAC address is not in the cache list, ARP broadcasts a packet asking which IP address owns some MAC address. The destination machine replies to the packet with its MAC address via an ARP reply (as we have learned above). So,  at this point, the transmitting computer has the data link layer addressing the information it needs to communicate with the remote computer. This information is then stored into the ARP cache.

An attacker can spoof this process by  sending ARP messages to an Ethernet switch or router with fake MAC  addresses in order to intercept the traffic of another computer.

In Linux, ARP spoofing can be done with [arpspoof or Ettercap](http://www.irongeek.com/i.php?page=security/arpspoof). For instance, if  your wlan0 is at 192.168.0.10 and the router is at 192.168.0.1, you can run:

```
$ arpspoof -i wlan0 -t 192.168.0.10 192.168.0.1
```

If you are in Windows, ARP cache poising can be crafted using [Cain & Abel](http://www.oxid.it/cain.html).


### Denial-of-Service

In  networks with very high demand, when you reroute traffic, everything  transmitted and received by the target system must first go through your analyzer system. This makes  your analyzer the bottleneck in the communication process and being suitable to cause [DoS](http://en.wikipedia.org/wiki/Denial-of-service_attack).

You might be able avoid all the traffic going through your analyzer system by using a feature called [asymmetric routing](http://www.cisco.com/web/services/news/ts_newsletter/tech/chalktalk/archives/200903.html).

---
## Wireless Sniffing

### The 802.11 Spectrum
The unique difference when capturing traffic from a **wireless local area network** (WLAN) is that the wireless spectrum is a **shared medium** (unlike wired networks, where each client has it own cable to the switch).

A single WLAN occupy a portion of the [802.11 spectrum](http://en.wikipedia.org/wiki/IEEE_802.11), allowing multiple systems to operate in the same physical medium. In the US, 11 channels are available and a WLAN can operate only one channel at time (and so the sniffing).

However, a technique called **channel hopping** allows quick change between channels to collect data. A tool to perform this is [kismet](https://www.kismetwireless.net/), which can hop up to 10 channels/second.



### Wireless NIC  modes

Wireless network cards can have four modes:

* **Managed**: when the wireless client connects directly to a wireless access point (WAP).

* **ad hoc mode**:   devices connect directly to each other, sharing the responsibility of  a WAP.

* **Master mode**: the NIC works with specialized software to allow the computer act as a WAP for other devices.

* **Monitor**: used to stop transmitting and receiving data, and start listening to the packets flying in the air.

To access the wireless extensions in Linux you can type:

```
$ iwconfig
```

To change the interface (for example eth1) to monitor mode, you type:
```
$ iwconfig eth1 mode monitor
$ iwconfig eth1 up
```

To change the channel of the interface:

```
$ iwconfig eth` channel 4
```





-------
## 更多相关资料：

- [Wireshark wiki](http://wiki.wireshark.org/)
- [Practical Packet Analysis, ](http://wiki.wireshark.org/)
- [Wireshark plugin  for writing dissectors in Python](https://github.com/ashdnazg/pyreshark)
- [Using Wireshark ti check for DNS Leaks](https://lilithlela.cyberguerrilla.org/?p=76081)
- [Publicly available PCAP files](http://www.netresec.com/?page=PcapFiles)
- [Malware PCAP files](http://contagiodump.blogspot.se/2013/08/deepend-research-list-of-malware-pcaps.html)
