## Extract md5 hashes

```
 # egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{32}(1|$)' *.txt | egrep -o '[a-fA-F0-9]{32}' > md5-hashes.txt
```

## An alternative could be with sed

```
# sed -rn 's/.*[^a-fA-F0-9]([a-fA-F0-9]{32})[^a-fA-F0-9].*/1/p' *.txt > md5-hashes
```

## Extract valid MySQL-Old hashes
```
# cat *.txt | grep -e "[0-7][0-9a-f]{7}[0-7][0-9a-f]{7}" > mysql-old-hashes.txt
```

## Extract blowfish hashes

```
# cat *.txt | grep -e "$2a$8$(.){75}" > blowfish-hashes.txt
```

## Extract Joomla hashes
```
# cat *.txt | egrep -o "([0-9a-zA-Z]{32}):(w{16,32})" > joomla.txt
```

## Extract VBulletin hashes
```
# cat *.txt | egrep -o "([0-9a-zA-Z]{32}):(S{3,32})" > vbulletin.txt
```

## Extract phpBB3-MD5
```
# cat *.txt | egrep -o '$H$S{31}' > phpBB3-md5.txt
```

## Extract Wordpress-MD5
```
# cat *.txt | egrep -o '$P$S{31}' > wordpress-md5.txt
```

## Extract Drupal 7
```
# cat *.txt | egrep -o '$S$S{52}' > drupal-7.txt
```

## Extract old Unix-md5
```
# cat *.txt | egrep -o '$1$w{8}S{22}' > md5-unix-old.txt
```

## Extract md5-apr1
```
# cat *.txt | egrep -o '$apr1$w{8}S{22}' > md5-apr1.txt
```

## Extract sha512crypt, SHA512(Unix)
```
# cat *.txt | egrep -o '$6$w{8}S{86}' > sha512crypt.txt
```

## Extract e-mails from text files
```
# cat *.txt | grep -E -o "[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+" > e-mails.txt
```

## Extract HTTP URLs from text files
```
# cat *.txt | grep http | grep -shoP 'http.*?[" >]' > http-urls.txt
```

## For extracting HTTPS, FTP and other URL format use
```
# cat *.txt | grep -E '(((https|ftp|gopher)|mailto)[.:][^ >"  ]*|www.[-a-z0-9.]+)[^ .,;   >">):]' > urls.txt
```

Note: 如果grep返回"Binary file (standard input) matches"那么使用下面这种方法

```
# cat *.log | tr '[00-1113-37177-377]' '.' | grep -E "Your_Regex"
```
或者

```
# cat -v *.log | egrep -o "Your_Regex"
```

## Extract Floating point numbers
```
# cat *.txt | grep -E -o "^[-+]?[0-9]*.?[0-9]+([eE][-+]?[0-9]+)?$" > floats.txt
```

## Extract credit card data
Visa
```
# cat *.txt | grep -E -o "4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" > visa.txt
```

MasterCard
```
# cat *.txt | grep -E -o "5[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" > mastercard.txt
```

American Express
```
# cat *.txt | grep -E -o "3[47][0-9]{13}" > americal-express.txt
```

Diners Club
```
# cat *.txt | grep -E -o "3(?:0[0-5]|[68][0-9])[0-9]{11}" > diners.txt
```

Discover
```
# cat *.txt | grep -E -o "6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" > discover.txt
```

JCB
```
# cat *.txt | grep -E -o "(?:2131|1800|35d{3})d{11}" > jcb.txt
```

AMEX
```
# cat *.txt | grep -E -o "3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}" > amex.txt
```

## Extract Social Security Number (SSN)
```
# cat *.txt | grep -E -o "[0-9]{3}[ -]?[0-9]{2}[ -]?[0-9]{4}" > ssn.txt
```

## Extract Indiana Driver License Number
```
# cat *.txt | grep -E -o "[0-9]{4}[ -]?[0-9]{2}[ -]?[0-9]{4}" > indiana-dln.txt
```

## Extract US Passport Cards
```
# cat *.txt | grep -E -o "C0[0-9]{7}" > us-pass-card.txt
```

## Extract US Passport Number
```
# cat *.txt | grep -E -o "[23][0-9]{8}" > us-pass-num.txt
```

## Extract US Phone Numberss
```
# cat *.txt | grep -Po 'd{3}[s-_]?d{3}[s-_]?d{4}' > us-phones.txt
```

## Extract ISBN Numbers
```
# cat *.txt | egrep -a -o "ISBN(?:-1[03])?:? (?=[0-9X]{10}$|(?=(?:[0-9]+[- ]){3})[- 0-9X]{13}$|97[89][0-9]{10}$|(?=(?:[0-9]+[- ]){4})[- 0-9]{17}$)(?:97[89][- ]?)?[0-9]{1,5}[- ]?[0-9]+[- ]?[0-9]+[- ]?[0-9X]" > isbn.txt
```

## WordList Manipulation
使用sed删除空格

```
# sed -i 's/ //g' file.txt
```

或者
```
# egrep -v "^[[:space:]]*$" file.txt
```

使用sed删除最后一个空格
```
# sed -i s/.$// file.txt
```

根据长度排序字典
```
# awk '{print length, $0}' rockyou.txt | sort -n | cut -d " " -f2- > rockyou_length-list.txt
```

将大写字母转换为小写字母或者进行相反的转换
```
# cat file.txt | tr [A-Z] [a-z] > lower-case.txt
```
```
# cat file.txt | tr [a-z] [A-Z] > upper-case.txt
```

使用sed删除空行
```
# sed -i '/^$/d' List.txt
```

使用sed删除特定字符
```
# sed -i "s/'//" file.txt
```

使用sed删除某一字符串
```
# echo 'This is a foo test' | sed -e 's/<foo>//g'
```

使用tr完成字符的替换
```
# cat emails.txt | tr '@' '#'
```
或者
```
# sed 's/@/#' file.txt
```

使用awk输出特定列
```
# awk -F "," '{print $3}' infile.csv > outfile.csv
```
或者

```
# cut -d "," -f 3 infile.csv > outfile.csv
```

Note: 如果你想要分隔第三列之后的所有列，使用
```
# cut -d "," -f 3- infile.csv > outfile.csv
```

使用urandom生成随机密码
```
# cat /dev/urandom | tr -dc 'a-zA-Z0-9._!@#$%^&*()' | fold -w 8 | head -n 500000 > wordlist.txt
```
```
# cat /dev/urandom | tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=' | fold -w 12 | head -n 4
```
```
# cat /dev/urandom | base64 | tr -d '[^:alnum:]' | cut -c1-10 | head -2
```
```
# cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 4
```
```
# cat /dev/urandom| tr -dc 'a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?='|fold -w 12| head -n 4| grep -i '[!@#$%^&*()_+{}|:<>?=]'
```
```
# < /dev/urandom tr -dc '[:print:]' |fold -w 10| head -n 10
```
```
# tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n2
```

使用tr删除括号
```
# cat in_file | tr -d '()' > out_file
```

查看你的文件夹中的所有文件
```
# ls -A | sed 's/regexp/& /g'
```

当cat无法处理特殊字符时，处理文本文件
```
# sed 's/([[:alnum:]]*)[[:space:]]*(.)(..*)/12/' *.txt
```

使用awk产生固定长度的字串
```
# awk 'length == 10' file.txt > 10-length.txt
```

合并两个不同的txt文件
```
# paste -d' ' file1.txt file2.txt > new-file.txt
```

更快的排序
```
# export alias sort='sort --parallel=<number_of_cpu_cores> -S <amount_of_memory>G ' && export LC_ALL='C' && cat file.txt | sort -u > new-file.txt
```

Mac to unix
```
# tr '15' '12' < in_file > out_file
```

Dos to Unix
```
# dos2unix file.txt
```

Unix to Dos
```
# unix2dos file.txt
```

将另一个文件中有的东西从这个文件中删除
```
# grep -F -v -f file1.txt -w file2.txt > file3.txt
```

使用sed分割特定行
```
# sed -n '1,100p' test.file > file.out
```

从PDF文件中创建特定字典
```
# pdftotext file.pdf file.txt
```

找到一个文件中某个字符串所在行的行号
```
# awk '{ print NR, $0 }' file.txt | grep "string-to-grep"
```


使用ag命令使以上的grep的常规表达完成得更快。下面的例子证明了它的速度：

```
# time cat *.txt | ack-grep -o "[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+" > /dev/null
real    1m2.447s
user    1m2.297s
sys 0m0.645s
```

```
# time cat *.txt | egrep -o "[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+" > /dev/null
real    0m30.484s
user    0m30.292s
sys 0m0.310s
```

```
# time cat *.txt | ag -o "[a-zA-Z0-9.#?$*_-]+@[a-zA-Z0-9.#?$*_-]+.[a-zA-Z0-9.-]+" > /dev/null
real    0m4.908s
user    0m4.820s
sys 0m0.277s
```
