# 逆向工程

* 目标:将一个x86二进制可执行文件转换为C源代码。
* 理解编译器如何将C转换为汇编代码。
* 底层操作系统结构和可执行文件格式。

---
## 101汇编

### 算术指令

```
mov eax,2   ; eax = 2
mov ebx,3   ; ebx = 3
add eax,ebx ; eax = eax + ebx
sub ebx, 2  ; ebx = ebx - 2
```

### 访问内存

```
mox eax, [1234]     ; eax = *(int*)1234
mov ebx, 1234       ; ebx = 1234
mov eax, [ebx]      ; eax = *ebx
mov [ebx], eax      ; *ebx = eax
```

### 条件分支

```
cmp eax, 2  ; compare eax with 2
je label1   ; if(eax==2) goto label1
ja label2   ; if(eax>2) goto label2
jb label3   ; if(eax<2) goto label3
jbe label4  ; if(eax<=2) goto label4
jne label5  ; if(eax!=2) goto label5
jmp label6  ; unconditional goto label6
```

### 函数调用

首先调用一个函数:

```
call func   ; store return address on the stack and jump to func
```
第一个操作是保存返回指针:
```
pop esi     ; save esi
```

在离开函数之前
```
pop esi     ; restore esi
ret         ; read return address from the stack and jump to it
```
---


## 现代编译器架构

**C代码** -->  分析 --> **中间表示** --> 优化 --> **低级中间表示** --> 寄存器分配 --> **x86汇编**

### 高级优化



#### 内联

例如，函数c:
```
int foo(int a, int b){
    return a+b
}
c = foo(a, b+1)
```
转换为  c = a+b+1


#### 循环展开

循环:
```
for(i=0; i<2; i++){
    a[i]=0;
}
```
变成
```
a[0]=0;
a[1]=0;
```

#### 循环不变式代码移动

循环:
```
for (i = 0; i < 2; i++) {
    a[i] = p + q;
}
```
变成:
```
temp = p + q;
for (i = 0; i < 2; i++) {
    a[i] = temp;
}
```

#### 公共子表达式消除

变量归因:
```
a = b + (z + 1)
p = q + (z + 1)
```

变成
````
temp = z + 1
a = b + z
p = q + z
```

#### 常量翻译和传递
任务:
```
a = 3 + 5
b = a + 1
func(b)
```

变成:
```
func(9)
```

#### 死代码消除

删除不必要的代码:
```
a = 1
if (a < 0) {
printf(“ERROR!”)
}
```
to
```
a = 1
```

### 低级优化

####  强度降低

代码如:
```
y = x * 2
y = x * 15
```

变成:
```
y = x + x
y = (x << 4) - x
```
#### 代码块重新排序

代码如:

```
if (a < 10) goto l1
printf(“ERROR”)
goto label2
l1:
    printf(“OK”)
l2:
    return;
```
变成:
```
if (a > 10) goto l1
printf(“OK”)
l2:
return
l1:
printf(“ERROR”)
goto l2
```


#### 寄存器分配

* 内存访问比寄存器要慢。
* 尽量在寄存器中尽可能多地容纳本地变量。
* 将局部变量映射到堆栈位置和寄存器的映射不是常量。

#### 指令调度

汇编代码:
```
mov eax, [esi]
add eax, 1
mov ebx, [edi]
add ebx, 1
```
变成:
```
mov eax, [esi]
mov ebx, [edi]
add eax, 1
add ebx, 1
```


---
## 工具文件夹

- X86 Win32 Cheat sheet
- Intro X86
- base conversion
- Command line tricks


----
## 其他工具

- gdb
- IDA Pro
- Immunity Debugger
- OllyDbg
- Radare2
- nm
- objdump
- strace
- ILSpy (.NET)
- JD-GUI (Java)
- FFDec (Flash)
- dex2jar (Android)
- uncompyle2 (Python)
- unpackers, hex editors, compilers

---
## 编码/ 二进制文件

```
file f1

ltrace bin

strings f1

base64 -d

xxd -r

nm

objcopy

binutils
```




---
## 在线参考资料

[逆向工程，这本书]: http://beginners.re/
[英特尔x86汇编指令集操作码表]: http://sparksandflames.com/files/x86InstructionChart.html


---
## 单程（IDA）

- 备忘单
- [IDA PRO](https://www.hex-rays.com/products/ida/support/download_freeware.shtml)



---
## gdb

- 命令和备忘单


```sh
$ gcc -ggdb -o <filename> <filename>.c

```

从一些命令开始:
```sh
$ gdb <program name> -x <command file>
```

例如:
```sh
$ cat command.txt
set disassembly-flavor intel
disas main
```

---
## 展开目标文件（objdump）

显示来自对象文件的信息:对象文件可以是一个中间文件
在编译过程中创建，但在链接或完全链接的可执行文件之前创建

```sh
$ objdump -d  <bin>
```

----
## （十六进制和二位数）hexdump & xxd
为规范十六进制和ASCII视图:
```
$hexdump -C
```
----
## xxd
做一个十六进制转换或者做相反的工作:
```
xxd hello > hello.dump
xxd -r hello.dump > hello
```

----

# 相关话题

* [Patrick Wardle: Writing OS X Malware](https://vimeo.com/129435995)
