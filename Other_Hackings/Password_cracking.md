# 密码

## 使用Hydra爆破密码

1. 下载[Hydra](https://www.thc.org/thc-hydra/)，并安装

```bash
$ ./configure
$ make
$ make install
```

2. 使用Burp查询认证类型(e.g. 使用FoxyProxy配置本地代理接口8080，这样burp可以破解它)。

2. 使用字典或者用户名字典运行hydra。如:

```bash
$ hydra -l <username> -P <password-list> -V <server> <service>
```
