# 密码学


### 提示：

- 通常，数据以base64或十六进制编码，其他情况下只是被压缩（gzip）:
	- 32个字节 --> md5 hash.
	- 40个字节 --> SHA1 hash.
	- 末尾等号 --> base64编码.
	- 只有字母，没有数字和特殊字符 --> Caesar, Vigenere, 或其他加密算法.
	- 提示密钥和签名 --> 可能是RSA.


---

## MD5

- [MD5散列算法](http://www.fastsum.com/support/md5-checksum-utility-faq/md5-hash.php)通常返回128bit值，所以两个随意选择的文本拥有相同散列的概率为1:2**128。



* 命令行:

```
$ echo -n password | md5sum
5f4dcc3b5aa765d61d8327deb882cf99
```

* 或者你可以使用python里的md5.md5().digest()

- md5 hashes: [点击此处](http://hash-killer.com/), [点击此处](http://www.md5this.com/), [点击此处](http://www.hashkiller.co.uk/).

- [md5sum](http://linux.about.com/library/cmd/blcmdl1_md5sum.htm)
- [md5 creator](http://www.md5-creator.com/)


### 可用的脚本

- Hash length extension attack
- Brute force hex digest chars



------

## SHA

- SHA-1输出160 bits值，所以出现重复的几率是1：2**160。

- [Hash maker](http://ratfactor.com/sha1).

### 脚本
- SHA-256 brute force


### 命令行

- Brute force:
```
import hashlib, itertools
hash = '6307c5441ebac07051e3b90d53c3106230dd9aa128601dcd5f63efcf824ce1ba'
ch = 'abcdef0123456789'
for a, b, c, d, e, f in itertools.product(ch, ch, ch, ch, ch, ch):
    if hashlib.sha256('ASIS_a9%s00f497f2eaa4372a7fc21f0d' % (a + b + c + d + e + f)).hexdigest() == hash:
        print 'ASIS_a9%s00f497f2eaa4372a7fc21f0d' % (a + b + c + d + e + f)
```




--------

## 移位密码


### 脚本
- Caesar
- Brute force rotation
- Pygenere
- Frequency analysis


### 在线工具:

- 频率分析: [点击此处](http://www.simonsingh.net/The_Black_Chamber/hintsandtips.html) and [点击此处](http://www.xarg.org/tools/caesar-cipher)

- [Cesar解密](http://www.xarg.org/tools/caesar-cipher/) and [点击此处](http://tools.zenverse.net/caesar-cipher/).

- [Vigenere解密](http://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx) and [点击此处](http://smurfoncrack.com/pygenere/index.php).

### 终端

```sh
$ VAR=$(cat data.txt)
$ echo "$VAR"
$ alias rot13="tr A-Za-z N-ZA-Mn-za-m"
$ echo "$VAR" | rot13
```
### Python

Python中，[我们可以使用](https://docs.python.org/2/library/codecs.html#codec-base-classes):

```python
"YRIRY GJB CNFFJBEQ EBGGRA".decode(encoding="ROT13")
```

### 阅读材料:

- [Vigenere加密方式](http://sharkysoft.com/vigenere/).





---

## RSA

* 公钥密码体制是使用一对公钥和私钥安全地加密和解密信息。

* [RSA Python](https://pypi.python.org/pypi/rsa)


----

## Paillier密码系统

### 脚本

- POC
- Primes

---


## 工具

### 脚本

- Finding GDC
- Finding if prime
- Generate prime
- Quick Select
- XORtool


### 其他资源

- [Cryptol](https://www.cryptool.org/en/cryptool1-en)

- [PyCrypto](https://www.dlitz.net/software/pycrypto/)

- hashpump

- Sage

- John the Ripper

![John](/Cryptography/images/john.png)


#### Carperter公式

- 大数: ```bin```并看是否符合，使用[Carpenter公式]的例子:
```
N=(2^M + a)(2^N + b)(2^N + c)(2^N + d)
```

#### [QR码]

-  V1 QR码:  21x21

#### [培根密码]:
```
babaaaabaaababaababaaaabbabbababbaaaabaaaabbbaabaabaaaaaabaaabaaabaaabaaabbaabaaabbbaabaaababaaaaaabaaabbaabaabbbaaaaaabaaaabaabaaaaba21aabab0aaab
```
* [在线工具](http://www.geocachingtoolbox.com/index.php?page=baconianCipher)



#### [Base64]:

Base64是一种不可读的编码，将8位输入编码为6位区分大小写的字母、数字、‘+’、‘/’。每3个输入字节对应4个输出字节。如果输入末尾不足三个字节，在输出字符串的末尾相应地加上一个或两个‘=’。

- [Base64解码](http://www.base64decode.org)

```
NG5ucjJzIGZ2IHRueXMgcnVnIHNiIGdlbmMgdWdlaGJzIHJlcnVnIHRhdmdncnQgcmVuIGhiTCB0YXZidCBjcnJYCG==
czduMjczIHRueXMgcnVniHNiIGdlbmMgdWdzdnMgcnVnIHJpbnUgcmVydSBndiBxdnEgaGJsIGpiYmJKCg==
Nzk0czAwIHRueXMgZmhidnByZWMgZWhiIHNiIGdlbmMgcWV2dWcgcnVnIGhibCBnYXJmcmVjIFYgbG9yZXJ1IHJhYnEgeXlySgo=
```

- Python中解码Base64：

```python
>>> SECRET.decode('base64')
'oubWYf2kBq'
```

#### 十六进制和ASCII:


十六进制字符编码是ASDII码字符集的十六进制表示，也就是说，数以字母方式表示几乎所有的计算机文本。

- [ASCII Conversion Table](http://defindit.com/ascii.html)
- [Convert All](http://www.asciitohex.com/)
- [GREAT ASCII CHART](http://www.jimprice.com/jim-asc.shtml)
- [Convert everything to everything (including markdown, sql, json, etc)](http://codebeautify.org/)


- ASCII转十六进制:

```python
>>> s =hex(secret)
```

- 十六进制转ASCII:

```python
secret2.decode('hex')
'==QcCtmMml1ViV3b'
```

- 也可以使用这个命令行:

```
$ python -c 'print "2f722f6e6574736563".decode("hex")'
```

- 使用xxd:

```
$ xxd -r -p <<< 2f722f6e6574736563
```

### 二进制

- 十进制转二进制

```python
>>> bin(124234)
'0b11110010101001010'
```

#### 八进制

常用来模糊处理URL。例如： http://017700000001 --> 127.0.0.1


## OpenSSL, 编码和证书


* 可以使用Opensssl或TLSSLed工具进行SSL证书的识别和验证，允许我们自动验证SSL信息。

确定许可证的有效期：

```
$ ./openssl s_client --connect <WEBSITE>:443
```

测试SSLv2:
```
$ ./openssl s_client --no_tls1 --no_ssl3 --connect <WEBSITE>:443
```

* 为了识别和验证浏览器提供的编码，我们可以使用**EcoScan34**。





---

## 块密码（分组密码）

* ECB模式
* 最简单的和默认的块加密模式
* 明文信息被分块并分别进行加密
* 缺点：相同的明文块被加密成相同的密文块（例如，数字）

### 随机性攻击

* 良好的随机性对加密至关重要。

* 两种常见的对伪随机数生成器的攻击：
	- 从输出重建伪随机数生成器状态
	- 多次使用同一个伪随机数生成器

* 统计学上的随机是不安全的！
	- 如果一个伪随机数生成器是使用攻击者可以改变的值作为种子数，那么他的状态可能会受到损害。

* 种子条件攻击:
	- 系统始终通常用于初始化伪随机数生成器
	- 一次提交10个或100个请求。用相同的系统时间初始化伪随机数生成器会得到同样的输出。




----



[SHA]:http://en.wikipedia.org/wiki/Secure_Hash_Algorithm
[MD5]: http://en.wikipedia.org/wiki/MD5
[Base64]: http://en.wikipedia.org/wiki/Base64
[Bacon's cipher]:http://en.wikipedia.org/wiki/Bacon's_ciphe
[Carpenter's Formula]:http://security.cs.pub.ro/hexcellents/wiki/writeups/asis_rsang
[pngcheck]: http://www.libpng.org/pub/png/apps/pngcheck.html
[karmadecay]: http://karmadecay.com/
[tineye]:  https://www.tineye.com/
[images.google.com]: https://images.google.com/?gws_rd=ssl
[base64 decoding]: http://www.motobit.com/util/base64-decoder-encoder.asp
[pnginfo]: http://www.stillhq.com/pngtools/
[namechk]: http://namechk.com
[QR Code]: http://en.wikipedia.org/wiki/QR_code



##  密码学术语表

* **对称密钥加密 (共享密钥加密)**：所有方有同样的密钥。在任意一组共享密钥用户中无法验证消息发送者。

* **密文分组链接模式(CBC)**: 对块进行操作。这是唯一适用的固定块密码。将明文分组与前一个密文分组进行OOR运算。大多数加密使用分组密码。

* **分组密码工作模式**: 有四种：
	1.  **电子密码本模式**（ECB）：标准模式。缺点：对于给定的密钥，相同的明文会被加密成相同的密文。
	2. **密文分组链接模式** (CBC)：最常使用。约定一个公开的**初始化向量**（与明文分组长度相同）。
	3. **密文反馈模式** (CFB): 如果明文输入较慢，明文一输入，就能产生密文。
	4. **输出反馈模式** (OFB)：一种为流密码创建密钥流的方式

* **数据加密标准(DES)**：1975。使用56位加上8位奇偶校验位密钥。加密64位明文并产生64位密文。代替了16次置换变换与15次转置变换。在1997年DES在24小时内被暴力破解了。

* **高级加密标准(AES)**：2002。处理128bit字符串。AES有128bit密钥和128bit密文和明文块。所以当AES用于加密，将处理128/8=16个消息块。代替了10次置换变换和10次转置变换。


* **流密码**：块与块的处理。块加密可以在固定块大小的工作模式中运行。CTR模式是流加密的最好选择。现代流加密属于对称密钥密码系统。

* **同步流密码**：简单地将明文与密钥流进行XOR运算。

* **RC4**：最常用的流加密，1987：
		1. 选择一个正数n，假设n=8.
		2. l = (位数)/n
		3. 密钥数组K_0...K_{2^n -1}的输入是n位字符串（从0到2^n -1的整数）。你把密钥输入进数组并根据需要重复。
		4. 算法即置换从0到2^n -1的整数。

* **初始化向量**：用于开始块加密的假设块。对于产生不同的输出流是必要的。不一定是私密的，但每次新的加密初始化时不能使用同样的密钥。

* **一次一密（OTP）**：不重复使用同一个密钥流。如果密钥流的每一个位都是真正随机产生的，那么意味着每一个位与前一个位之间都是相互独立的。所以你不能使用一个短的初始化种子或密钥，然后用它来产生密钥流。（比如：抛硬币）


-----

* **非对称密钥加密（公钥密码）**：每一方都有一组用于访问相同密文的密钥。主要用途：
	1. 对称密码系统中共享密钥
	2. 数字签名
	3. 很少用于消息交换因为速度比对称密码慢

* **标准密钥交换协议**：RSA, Diffie-Hellman, El Gamal.

* **加密签名**: 通过用发送者的公钥和私钥加密消息摘要将消息摘要与特定的公钥相联系。

* **RSA**：如果gcd(m,n)=1，并且a = 1(mod f(n))，那么m^a = m (mod n)。
	1. Bob选择两个素数p, q（约1e150位）.
	2. 计算n = pq ~ 1e300，f(n)=(p-1)(q-1).
	3. 利用gcd(e, f(n)) = 1，找到一个e，计算1/e mod f(n) = d.
	4. 公开(n,e)，保密d, p, q
	5. Alice想给Bob发送消息M（可能是一个被编码为数字的AES密钥）0<=M < n. 如果消息长于n，那么她将对M进行分组
	6. Alice找到Bob的n,e，计算M^e mod n = C，把C发送给Bob
	7. Bob计算C^d mod n得到M，因为C^d = (M^e)^d = M
	8. 如果Eve得到了C，没有Bob的d是不能揭秘信息的.

要求：

	* gcd(p-1, q-1)很小
	* p-1和q-1要有一个大的素数公因子
	* p和q不能相差太近(ration ~ 4).
	* e可以为一个较小的数：3，17=2^4 +1，或者65537=2^16 +1：不断乘方扩大较小的e，用二进制表示时，e没有很多1。


个人使用1024位（n ~ 1e308）。
公司使用2048位（n ~ 1e617）。
1990年早期，通常使用512位（n ~ 1e154）。2009年一个RSA数n~2^768 ≈ 1e232被分解。

*  **ElGamal**：用来交换对称加密的密钥
	1. Bob选择一个有限域，一个生成器和一个私钥。
	2. Alice加密M后发送给Bob。她选择一个随机的会话并发送生成器和私钥。


* **椭圆曲线密码** (ECC)：与RSA安全性相同，但拥有密钥极短（1/6 bits）。它在密钥协商和减小存储计算（如智能卡）方面非常有用。
	- 椭圆曲线是一个满足y^2 + a_1 xy + a_3 y = x^3 + a_2 x^2 + a_4 x + a_6的曲线。
	- 所有的三次曲线都可以转化为这种形式。曲线在无限大或0点处封闭。

* **椭圆曲线Diffie-Hellman密钥交换** (ECDH)：选择一个有限域，在域中选定一些椭圆曲线和系数，和一个伪随机生成点。每个用户都有一个私密数字和公开密钥点。

* **椭圆曲线ElGamal消息交换**：如何将消息编码为一个点？使用无限域。

----

* **散列函数**：接收一个不定长度输入，产生一个固定长度输出。必须是不可逆且无重复的。最简单的是CRC校验和加密哈希函数（SHA-1, SHA-256, MD5）。
	- **单向**性：给定输出y，很难得到输入，比如求得H(x) = y中的x。比如说，密码通常用散列函数来保存：当你登陆，系统会计算你输入密码的哈希值并与已存储的值进行比对（你无法反向计算）。
	- **抗弱碰撞性**：给定输入x，很难找到x' ̸= x，使得H(x) = H(x'′')。
	- **抗强碰撞性**: 很难找到x和x'，且x ̸= x'，使得H(x) = H(x').
	- 在所有主流的散列函数中(MD5, SHA-0, SHA-1, SHA-2)：只有SHA-2有抗强碰撞性。另外，SHA-2与SHA-1相似，所以可能不是所有SHA-2函数都有抗强碰撞性。

* **MAC**：带密钥的散列函数。我们只需要将已知的初始化向量换成一个共享的密钥。
	- 例子：f是AES加密, t = m = 128。将消息分成128位的块。如果消息长度不是128的倍数，那么在消息末尾添加相应位数的0。第一轮AES加密的密钥是初始化向量。第二轮AES加密的密钥是第一轮AES的结果，依此类推。最终的输出是消息的散列值。这并不是一个安全的散列函数，但作为消息验证码来说是可以使用的。

* **基于散列函数的MAC(HMAC)**：它是一个发起者验证，通过将某些形式的私钥加入哈希函数来验证消息的来源。与所有的共享密钥系统有同样的弱点。

* **诱饵攻击**：在已成熟的散列函数中发现弱点。攻击者利用散列函数趋势，在某些输入范围内制造碰撞。这样，攻击者可以获取两个产生相同散列值的输入。


* **MD5散列函数**：函数f读取两个输入：一个128为字符串和一个512位字符串，输出128位字符串。设X为512位字符串。对于MD5，我们可以将一个32位字符串称为一个字。所以X有16个字。设X[0]为第一个字，X[1]是下一个，...， X[15]为最后一个字。

* **SHA3**：在2012年被NIST选中，具有高强度的无碰撞性。SHA-3固定长度输入，输出256位.


-----------

* **网络安全**：有两个主要的用于为互联网提供安全的协议（加密和认证）：TLS and IPSec.

* **传输层安全协议**: 这个过程被称为安全链路层（SSL），现在被TLS替代。用RSA共享AES的密钥 (比如说用来加密密码）。

* **互联网安全协议** (IPSec)：是TLS的竞争者，不如TLS高效，被用在VPN中。

* **时间戳（timestamping）**：如果Alice想要签名一个消息， 但后来她不希望此消息被签名，那么她可以匿名发布自己的私钥，并且说任何人都可以完成的签名。这称为否认。所以如果有人收到了Alice的签名，他可以要求Alice使用数字时间戳服务。

* **计算机网络授权协议**(Kerberos)：为不安全的封闭系统提供的第三方认证协议。它用来在没有公钥密码的情况下安全地认证第三方的身份。身份认证服务器使用票据授权服务来验证客户端身份。

* **盐**（Salt）：在消息中加入任意值使得两个消息不产生相同的哈希值。不可以使用相同的盐加密不同消息。除了存储哈希值，还需保存盐，以便复现摘要。必须被保护。一个23位的盐给预先计算字典增加了40亿(2^32)的计算时间。

	- 与密码串接的字符串称为盐。对每个用户账号来说需要使用不同的盐。对于非SSL/TLS应用，比如KERBEROS and UNIX来说，盐是公开的。

	- 两个人有相同的密码，但他们的密码不会有相同的哈希值。在Kerberos中，认证服务器将哈希值用一个仅自己知道的密码加密。

	- Linux：在密码文件中，以前有一个盐和一个加盐后的密码的哈希值，现在是一个‘*’。第二个隐藏文件是密码文件，被称为影子文件。它使用仅对系统管理员已知的密码加密。影子文件包含userid, salt, hash(salt,password).

* **彩虹表**（Rainbow Tables）：未加盐，使得密码的哈希值难以抵御预先计算攻击的。


---

* **量子密码技术**: 两种在不见面的情况下共享对称加密密钥的方式: 公钥密码；量子密码。几千米外有效。可以侦测窃听。
	- 一个光子有两对极化状态。如果你使用错误的基态测量，你就得到了随机的结果，并影响以后的测量。
	- Alice给Bob发送一个光子流。每个光子都被随机分配一个极（-1, 0, 1, 0）。
	- Bob随机选择每个光子的基态。每次他选择了正确的基态，就可以正确的测量极化，否则就只能使用随机态。
	- 现在Bob联系Alice并告诉她他所设置的基态。Alice告诉他哪些是正确的的，错误的将被丢弃。
	- 当Bob正确的设置了基态，他们将拥有同样的极化，即被转换为0或1。
	- 平均说来，Alice发送2n位，会得到n位。所以为了得到128为，她必须发送256位。、
	- 为了侦测窃听，Alice和Bob协商检测由Alice随机选择的部分位。
	- 窃听者Eve可以进行中间人攻击，并假装Alice或Bob，所以量子密码技术需要身份认证。


---
* **密码分析**：有三种类型
	- **唯密文攻击**: 攻击者试图解密密文但没有相应的明文。攻击者知道加密方式但没有密钥，或者攻击者不知道加密方式（或者加密方式不确定）。
	- **已知明文攻击**: 攻击者已知一些明文/密文对。
	- **选择明文攻击**: 攻击者可以选择明文并得到相应的密文。
---

## 参考文献

- [Crypto Intro](http://math.scu.edu/~eschaefe/book.pdf)
