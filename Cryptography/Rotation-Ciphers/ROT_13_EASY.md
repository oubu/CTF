```
VAR=$(cat data.txt)
echo "$VAR"
alias rot13="tr A-Za-z N-ZA-Mn-za-m"
echo "$VAR" | rot13
```
----


在Python中我们可以使用: ```"YRIRY GJB CNFFJBEQ EBGGRA".decode(encoding="ROT13")```
https://docs.python.org/2/library/codecs.html#codec-base-classes

---

在线工具: 

http://www.xarg.org/tools/caesar-cipher/
