# Socket模块(by bt3)

Python的[socket](https://docs.python.org/2/library/socket.html)模块包含所有用来写[TCP](http://en.wikipedia.org/wiki/Transmission_Control_Protocol)/[UDP](http://en.wikipedia.org/wiki/User_Datagram_Protocol)客户端和服务器的工具，包括[原始套接字](http://en.wikipedia.org/wiki/Raw_socket)。真的很棒！


---
## TCP客户端

让我们从起点开始。无论什么时候你想要使用**socket**模块创建一个TCP连接，你需要做两件事：创建套接字对象，然后在某个端口与一个主机相连接：

```python
client = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
client.connect(( HOST, PORT ))
```

**AF_INET**参数用来定义标准的IPv4地址(其他选项有*AF_UNIX*和*AF_INET6*)。 **SOCK_STREAM**参数表明这是一个 **TCP** 连接(其他选项包括*SOCK_DGRAM*,  *SOCK_RAW*, *SOCK_RDM*, *SOCK_SEQPACKET*)。

好了，现在你要做的下面一件事就是使用socket的**send**和**recv**方法发送和接受数据。这样我们就可以完成第一个脚本！让我们把所有东西整合起来来创建我们的TCP客户端：


```python
import socket

HOST = 'www.google.com'
PORT = 80
DATA = 'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n'

def tcp_client():
    client = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
    client.connect(( HOST, PORT ))
    client.send(DATA)
    response = client.recv(4096)
    print response

if __name__ == '__main__':
    tcp_client()
```

这个脚本的简洁性建立在对套接字做出如下假设的基础上：

* 我们的 *连接总是会成功*，
* *服务器段总是在等待我们先发送数据* (不同于服务器端发送数据然后等待相应），并且
* 服务器端总是会在 *很短时间* 内向我们返回消息

让我们运行这个脚本(注意我们得到了 *Moved Permanently* 因为Google建立了HTTPS连接):

```bash
$  python tcp_client.py
HTTP/1.1 301 Moved Permanently
Location: http://www.google.com/
Content-Type: text/html; charset=UTF-8
Date: Mon, 15 Dec 2014 16:52:46 GMT
Expires: Wed, 14 Jan 2015 16:52:46 GMT
Cache-Control: public, max-age=2592000
Server: gws
Content-Length: 219
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
Alternate-Protocol: 80:quic,p=0.02

<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
```

就是这么简洁~

----------
## TCP服务器

让我们继续来写一个 *多线程* 的TCP服务器。我们要用到Python的[threading](https://docs.python.org/2/library/threading.html)模块。

首先我们要定义IP地址和想要服务器监听的端口号。然后我们定义一个 **handle_client** 函数来启动一个线程处理客户端连接。这个函数接收客户端套接字，从客户端读取数据，发送 **ACK** 消息。

我们服务器的主函数 **tcp_server** 创建了一个服务器套接字，并开始监听端口和IP (我们将连接的最大backlog设置为5)。然后它将运行一个循环等待客户端连接。当客户端连接开始时，它将接收客户端套接字(客户端变量变为 **addr** 变量)。

这里，程序会为我们上面提到的 **handle_client** 函数创建一个线程对象：

```python
import socket
import threading

BIND_IP = '0.0.0.0'
BIND_PORT = 9090

def handle_client(client_socket):
    request = client_socket.recv(1024)
    print "[*] Received: " + request
    client_socket.send('ACK')
    client_socket.close()

def tcp_server():
    server = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
    server.bind(( BIND_IP, BIND_PORT))
    server.listen(5)
    print"[*] Listening on %s:%d" % (BIND_IP, BIND_PORT)

    while 1:
        client, addr = server.accept()
        print "[*] Accepted connection from: %s:%d" %(addr[0], addr[1])
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

if __name__ == '__main__':
    tcp_server()
```

我们在一个终端上运行这个脚本，并在另一个终端上运行客户端脚本（就是我们之前看到的那个）。运行服务器：

```bash
$ python tcp_server.py
[*] Listening on 0.0.0.0:9090
```

运行客户端脚本(我们使它连接到127.0.0.1:9090):

```bash
$ python tcp_client.py
ACK
```

现在，返回服务器的终端，我们可以看到已经成功地建立了连接：

```bash
$ python tcp_server.py
[*] Listening on 0.0.0.0:9090
[*] Accepted connection from: 127.0.0.1:44864
[*] Received: GET / HTTP/1.1
```

Awesome!



----------
## UDP客户端

UDP是TCP的一个替代协议。和TCP一样，它用来将包从一个主机转发到另一个主机。和TCP不同的是，它是一种 *无连接的* 和 *无连接导向的* 协议。这意味着一个UDP主机不通过建立一个可靠的连接管道，来从其他主机接收包。

对上面的脚本做一些小改动，我们便可以建立一个UDP客户端连接：

* 使用 **SOCK_DGRAM** 代替 **SOCK_STREAM**,
* 因为UDP是一个无连接的协议，所以我们不需要提前建立连接，并且
* 我们使用 **sendto** 和 **recvfrom** 代替 **send** 和 **recv**.

```python
import socket

HOST = '127.0.0.1'
PORT = 9000
DATA = 'AAAAAAAAAA'

def udp_client():
    client = socket.socket( socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(DATA, ( HOST, PORT ))
    data, addr = client.recvfrom(4096)
    print data, adr

if __name__ == '__main__':
    udp_client()
```

-----

## UDP服务器

下面是一个非常简单的UDP服务器的例子。注意这里面没有 **listen** 或 **accept**：


```python
import socket

BIND_IP = '0.0.0.0'
BIND_PORT = 9000

def udp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(( BIND_IP, BIND_PORT))
    print "Waiting on port: " + str(BIND_PORT)

    while 1:
        data, addr = server.recvfrom(1024)
        print data

if __name__ == '__main__':
    udp_server()
```

你可以在一个终端中运行服务器，在另一个终端中运行客户端，进行测试。它将成功运行，过程也十分有趣。

---------
## 一个非常简单的Netcat客户端

有时候，当你侵入一个系统时，你想要[netcat](http://netcat.sourceforge.net/)，但可能你没有安装。但是，如果你有Python，你就可以创建一个netcat网络的客户端和服务器。

下面这个脚本就是一个可以完成的最简单的netcat客户端的建立脚本，由我们的TCP客户端脚本添加循环后扩展而来。

另外，现在我们将使用 **sendall** 方法。不同于 **send**，它会持续地发送数据直到所有的数据被发送完或者产生了错误（没有成功的返回结果）。

我们也需要使用 **close** 来释放资源。它并不会立刻关闭连接，所以我们使用 **shutdown** 来及时关闭连接：

```python
import socket

PORT = 12345
HOSTNAME = '54.209.5.48'

def netcat(text_to_send):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(( HOSTNAME, PORT ))
    s.sendall(text_to_send)
    s.shutdown(socket.SHUT_WR)

    rec_data = []
    while 1:
        data = s.recv(1024)
        if not data:
            break
        rec_data.append(data)

    s.close()
    return rec_data

if __name__ == '__main__':
    text_to_send = ''
    text_recved = netcat( text_to_send)
    print text_recved[1]
```




---------
## 一个完整的Netcat客户端和服务器

让我们拓展我们之前的例子，来写一个完整的netcat的客户端和服务器的程序。

为了完成这个任务，我们将使用两个特别的Python模块：[getopt](https://docs.python.org/2/library/getopt.html)，用来作为命令行选项的解析器(和C的getopt()很像)和[subprocess](https://docs.python.org/2/library/subprocess.html)，用于产生一个新的进程。


### The Usage Menu

我们写的第一个函数是 **usage**，以及我们的工具需要的选项：

```python
def usage():
    print "Usage: netcat_awesome.py -t <HOST> -p <PORT>"
    print "  -l --listen                  listen on HOST:PORT"
    print "  -e --execute=file            execute the given file"
    print "  -c --command                 initialize a command shell"
    print "  -u --upload=destination      upload file and write to destination"
    print
    print "Examples:"
    print "netcat_awesome.py -t localhost -p 5000 -l -c"
    print "netcat_awesome.py -t localhost -p 5000 -l -u=example.exe"
    print "netcat_awesome.py -t localhost -p 5000 -l -e='ls'"
    print "echo 'AAAAAA' | ./netcat_awesome.py -t localhost -p 5000"
    sys.exit(0)
```

## 解析主函数中的参数

现在，在我们具体研究特定函数之前，让我们看看 **主** 函数都做了什么。首先，它都去了参数并使用 **getopt** 解析了它们。然后，它加载参数。最后程序使用常量 **LISTEN** 判定它是一个客户端还是一个服务器：

```python
import socket
import sys
import getopt
import threading
import subprocess

LISTEN   = False
COMMAND  = False
UPLOAD   = False
EXECUTE  = ''
TARGET   = ''
UP_DEST  = ''
PORT     = 0

def main():
    global LISTEN
    global PORT
    global EXECUTE
    global COMMAND
    global UP_DEST
    global TARGET

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:],"hle:t:p:cu", \
            ["help", "LISTEN", "EXECUTE", "TARGET", "PORT", "COMMAND", "UPLOAD"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-l', '--listen'):
            LISTEN = True
        elif o in ('-e', '--execute'):
            EXECUTE = a
        elif o in ('-c', '--commandshell'):
            COMMAND = True
        elif o in ('-u', '--upload'):
            UP_DEST = a
        elif o in ('-t', '--target'):
            TARGET = a
        elif o in ('-p', '--port'):
            PORT = int(a)
        else:
            assert False, "Unhandled option"

    # NETCAT client
    if not LISTEN and len(TARGET) and PORT > 0:
        buffer = sys.stdin.read()
        client_sender(buffer)

    # NETCAT server
    if LISTEN:
        if not len(TARGET):
            TARGET = '0.0.0.0'
        server_loop()

if __name__ == '__main__':
    main()
```


### 客户端函数

**client_sender** 函数和我们上面看到的客户端代码片很像。它创建了一个套接字对象，然后在一个循环中发送/接收数据：

```python
def client_sender(buffer):
    client = socket.socket( socket.AF_INET, socket.SOCK_STREAM )

    try:
        client.connect(( TARGET, PORT ))

        # test to see if received any data
        if len(buffer):
            client.send(buffer)

        while True:
            # wait for data
            recv_len = 1
            response = ''

            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response += data
                if recv_len < 4096:
                    break
            print response

            # wait for more input until there is no more data
            buffer = raw_input('')
            buffer += '\n'

            client.send(buffer)

    except:
        print '[*] Exception. Exiting.'
        client.close()
```

### 服务器函数
现在，让我们看一下 **server_loop** 函数，它和我们上面看到的TCP服务器脚本很像：

```python
def server_loop():
    server = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    server.bind(( TARGET, PORT ))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()
        client_thread = threading.Thread( target =client_handler, \
                args=(client_socket,))
        client_thread.start()
```

**threading** 函数调用 **client_handler** ，以上传文件或者执行命令(在一个特殊的*NETCAT* shell中):

```python

def client_handler(client_socket):
    global UPLOAD
    global EXECUTE
    global COMMAND

    # check for upload
    if len(UP_DEST):
        file_buf = ''

        # keep reading data until no more data is available
        while 1:
            data = client_socket.recv(1024)
            if data:
                file_buffer += data
            else:
                break

        # try to write the bytes (wb for binary mode)
        try:
            with open(UP_DEST, 'wb') as f:
                f.write(file_buffer)
                client_socket.send('File saved to %s\r\n' % UP_DEST)
        except:
            client_socket.send('Failed to save file to %s\r\n' % UP_DEST)

    # Check for command execution:
    if len(EXECUTE):
        output = run_command(EXECUTE)
        client_socket.send(output)

    # Go into a loop if a command shell was requested
    if COMMAND:
        while True:
            # show a prompt:
            client_socket.send('NETCAT: ')
            cmd_buffer = ''

            # scans for a newline character to determine when to process a command
            while '\n' not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            # send back the command output
            response = run_command(cmd_buffer)
            client_socket.send(response)
```

观察上面脚本的最后两行。这个程序调用了一个使用 **subprocess** 库的 **run_command** 函数来构造一个进程建立端口。它给出了一系列启动和与客户端程序交互的方法：

```python
def run_command(command):
    command = command.rstrip()
    print command
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, \
                shell=True)
    except:
       output = "Failed to execute command.\r\n"
    return output
```

### 启动服务器和客户端
现在我们将所有的东西整合起来。在一个客户端里面运行服务器脚本，在另一个里面运行客户端脚本。作为服务器运行：

```bash
$ netcat_awesome.py -l -p 9000 -c
```

作为客户端(要获取shell，CTRL+D来EOF):

```bash
$ python socket/netcat_awesome.py -t localhost -p 9000
NETCAT:
ls
crack_linksys.py
netcat_awesome.py
netcat_simple.py
reading_socket.py
tcp_client.py
tcp_server.py
udp_client.py
NETCAT:
```

### The Good 'n' Old Request

此外，我们可以使用客户端来发送响应：

```bash
$  echo -ne "GET / HTTP/1.1\nHost: www.google.com\r\n\r\n" | python socket/netcat_awesome.py -t www.google.com -p 80
HTTP/1.1 200 OK
Date: Tue, 16 Dec 2014 21:04:27 GMT
Expires: -1
Cache-Control: private, max-age=0
Content-Type: text/html; charset=ISO-8859-1
Set-Cookie: PREF=ID=56f21d7bf67d66e0:FF=0:TM=1418763867:LM=1418763867:S=cI2xRwXGjb6bGx1u; expires=Thu, 15-Dec-2016 21:04:27 GMT; path=/; domain=.google.com
Set-Cookie: NID=67=ZGlY0-8CjkGDtTz4WwR7fEHOXGw-VvdI9f92oJKdelRgCxllAXoWfCC5vuQ5lJRFZIwghNRSxYbxKC0Z7ve132WTeBHOCHFB47Ic14ke1wdYGzevz8qFDR80fpiqHwMf; expires=Wed, 17-Jun-2015 21:04:27 GMT; path=/; domain=.google.com; HttpOnly
P3P: CP="This is not a P3P policy! See http://www.google.com/support/accounts/bin/answer.py?hl=en&answer=151657 for more info."
Server: gws
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
Alternate-Protocol: 80:quic,p=0.02
Transfer-Encoding: chunked
(...)
```

很酷吧？

------

## TCP代理

在转发流量和评估基于网络的软件时，TCP代理是十分有用的(例如，但你无法运行[Wireshark](http://bt3gl.github.io/wiresharking-for-fun-or-profit.html)或者你无法加载你正在使用的机器的驱动程序或工具）。

要创建代理，我们需要验证我们是否需要 *先启动到远程端的连接* 。它将在进入主循环之前请求数据，一些服务器守护程序希望你首先执行这个操作（例如，FTP服务器首先发送banner）。我们把这个信息叫做 **receive_first**。


### 主函数
所以，让我们 **主** 函数开始。首先，我们来定义用法，它应该有4个多的参数和 **receive_first**。然后让我们检测参数到变量，并启动一个监听套接字：

```python
import socket
import threading
import sys

def main():
    if len(sys.argv[1:]) != 5:
        print "Usage: ./proxy.py <localhost> <localport> <remotehost> <remoteport> <receive_first>"
        print "Example: ./proxy.py 127.0.0.1 9000 10.12.122.1 9999 True"
        sys.exit()

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    if sys.argv[5] == 'True':
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)
```


### 服务器循环函数

就像我们之前开始创建一个套接字并将它和端口和主机绑定。然后我们需要开始一个循环，并接受将要进行的连接，然后为新的连接创建一个新的线程：

```python
def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind(( local_host, local_port))
    except:
        print "[!!] Failed to listen on %s:%d" % (local_host, local_port)
        sys.exit()

    print "[*] Listening on %s:%d" % (local_host, local_port)
    server.listen(5)

    while 1:
        client_socket, addr = server.accept()
        print "[==>] Received incoming connection from %s:%d" %(addr[0], addr[1])

        # start a thread to talk to the remote host
        proxy = threading.Thread(target=proxy_handler, \
            args=(client_socket, remote_host, remote_port, receive_first))
        proxy.start()
```

### 代理Handler函数

在上面的程序的最后两行，这个程序给我们即将展示的 **proxy_handler** 函数启动了一个新的线程。这个函数创建了一个TCP套接字，然后和远端主机和端口进行连接。然后它将校验 **receive_first** 参数。最后，进入一个循环：

1. 从本地主机读取（使用 **receive_from** 函数)，
2. 加载 (使用 **hexdump** 函数)，
3. 发送给远端主机（使用 **response_handler** 和 **send** 函数)，
4. 从远端主机读取(使用 **receive_from** 函数)，
5. 加载(使用 **hexdump** 函数)，然后
6. 发送给本地主机(使用 **response_handler** 和 **send** 函数)

这个程序将会持续运行，直到本地和远端的缓冲区都为空时循环终止。让我们来看一下：

```python
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect(( remote_host, remote_port ))

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)
        remote_buffer = response_handler(remote_buffer)

        # if we have data to send to client, send it:
        if len(remote_buffer):
            print "[<==] Sending %d bytes to localhost." %len(remote_buffer)
            client_socket.send(remote_buffer)

    while 1:
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            print "[==>] Received %d bytes from localhost." % len(local_buffer)
            hexdump(local_buffer)
            local_buffer = request_handler(local_buffer)
            remote_socket.send(local_buffer)
            print "[==>] Sent to remote."

        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):
            print "[==>] Received %d bytes from remote." % len(remote_buffer)
            hexdump(remote_buffer)
            remote_buffer = response_handler(remote_buffer)
            client_socket.send(remote_buffer)
            print "[==>] Sent to localhost."

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print "[*] No more data. Closing connections"
            break
```


**receive_from** 函数接收一个套接字对象并执行接收，转储包的内容：

```python
def receive_from(connection):
    buffer = ''
    connection.settimeout(2)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except:
        pass
    return buffer
```

**response_handler** 函数用于修改进入的流量的数据包内容（例如，执行fuzzing，认证测试等）。出站时，**request_handler** 函数执行相同内容：

```python
def request_handler(buffer):
    # perform packet modifications
    buffer += ' Yaeah!'
    return buffer

def response_handler(buffer):
    # perform packet modifications
    return buffer
```


最后， **hexdump** 函数使用十六进制和ASCII字符输出包的细节：

```python
def hexdump(src, length=16):
    result = []
    digists = 4 if isinstance(src, unicode) else 2
    for i in range(len(src), lenght):
        s = src[i:i+length]
        hexa = b' '.join(['%0*X' % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04X %-*s %s" % (i, length*(digits + 1), hexa, text))
```



### 运行我们的代理

现在我们只需要用某个服务器来运行我们的脚本。比如，使用标准端口21的FTP服务器：

```sh
$ sudo ./tcp_proxy.py localhost 21 ftp.target 21 True
[*] Listening on localhost:21
(...)
```




---
## 其他东西：socket对象方法

另外，让我们来看一下 **socket** 模块中 **socket** 对象提供的所有方法。我认为掌握这个列表是很有用的：

* **socket.accept()**: 接受连接

* **socket.bind(address)**: 绑定地址到套接字

* **socket.close()**: 关闭套接字

* **socket.fileno()**: 返回套接字文件描述符

* **socket.getpeername()**: 返回连接到当前套接字的远端地址

* **socket.getsockname()**: 返回当前套接字的地址

* **socket.getsockopt(level, optname[, buflen])**: 返回指定套接字的参数

* **socket.listen(backlog)**: 开始对连接的监听。backlog参数定了最大的连接数

* **socket.makefile([mode[, bufsize]])**: 创建并返回一个与该套接字相关联的文件

* **socket.recv(bufsize[, flags])**: 接收TCP套接字数据

* **socket.recvfrom(bufsize[, flags])**: 接收UDP套接字数据

* **socket.recv_into(buffer[, nbytes[, flags]])**: 从套接字接收n 字节，将数据转储到缓冲区而不是创建一个新的字符串

* **socket.send(string[, flags])**: 发送TCP数据

* **socket.sendall(string[, flags])**: 完整发送TCP数据

* **socket.sendto(string, address)**: 发送UDP数据

* **socket.setblocking(flag)**: 设置套接字的阻塞与非阻塞模式

* **socket.settimeout(value)**: 设置阻塞套接字操作的超时时间

* **socket.gettimeout()**: 返回阻塞套接字操作的超时时间

* **socket.setsockopt(level, optname, value)**: 设定指定套接字的参数

* **socket.shutdown(how)**: 关闭连接的两个部分

* **socket.family**: 套接字家族

* **socket.type**: 套接字

* **socket.proto**: 套接字协议







## 更多相关资料：

- [Python's Socket Documentation](https://docs.python.org/2/library/socket.html)
- [Black Hat Python](http://www.nostarch.com/blackhatpython).
- [My Gray hat repo](https://github.com/bt3gl/My-Gray-Hacker-Resources).
- [A TCP Packet Injection tool](https://github.com/OffensivePython/Pinject/blob/master/pinject.py).
- [An asynchronous HTTP Proxy](https://github.com/OffensivePython/PyProxy/blob/master/PyProxy.py).
- [A network sniffer at the Network Layer](https://github.com/OffensivePython/Sniffy/blob/master/Sniffy.py).
- [A Guide to Network Programming in C++](http://beej.us/guide/bgnet/output/html/multipage/index.html).

----

