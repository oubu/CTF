xortool.py
====================

一个用来分析xor的工具:

  - 猜测密钥长度（基于相同的字符）
  - 猜测密钥（基于频率最高的字符）

密钥
---------------------

! *python3不可用，请使用python 2.x*

<pre>
  xortool [-h|--help] [OPTIONS] [&lt;filename&gt;]
Options:
  -l,--key-length       length of the key (integer)
  -c,--char             most possible char (one char or hex code)
  -m,--max-keylen=32    maximum key length to probe (integer)
  -x,--hex              input is hex-encoded str
  -b,--brute-chars      brute-force all possible characters
  -o,--brute-printable  same as -b but will only use printable
                        characters for keys
</pre>

例子
---------------------

<pre>
# xor is tools/xor.py
tests $ xor -f /bin/ls -s "secret_key" > binary_xored

tests $ xortool binary_xored
The most probable key lengths:
   2:   5.0%
   5:   8.7%
   8:   4.9%
  10:   15.4%
  12:   4.8%
  15:   8.5%
  18:   4.8%
  20:   15.1%
  25:   8.4%
  30:   14.9%
Key-length can be 5*n
Most possible char is needed to guess the key!

# 00 is the most frequent byte in binaries
tests $ xortool binary_xored -l 10 -c 00
...
1 possible key(s) of length 10:
secret_key

# decrypted ciphertexts are placed in ./xortool_out/Number_&lt;key repr&gt;
# ( have no better idea )
tests $ md5sum xortool_out/0_secret_key /bin/ls
29942e290876703169e1b614d0b4340a  xortool_out/0_secret_key
29942e290876703169e1b614d0b4340a  /bin/ls
</pre>

最常见的用途就是破解加密文件和找到频率最高的字母（对于二进制通常是00，对于文本文件通常是20）——长度会被自动选择：

<pre>
tests $ xortool tool_xored -c 20
The most probable key lengths:
   2:   5.6%
   5:   7.8%
   8:   6.0%
  10:   11.7%
  12:   5.6%
  15:   7.6%
  20:   19.8%
  25:   7.8%
  28:   5.7%
  30:   11.4%
Key-length can be 5*n
1 possible key(s) of length 20:
an0ther s3cret \xdd key
</pre>

这里，密钥比默认的32位限度更长：

<pre>
tests $ xortool ls_xored -c 00 -m 64
The most probable key lengths:
   3:   3.3%
   6:   3.3%
   9:   3.3%
  11:   7.0%
  22:   6.9%
  24:   3.3%
  27:   3.2%
  33:   18.4%
  44:   6.8%
  55:   6.7%
Key-length can be 3*n
1 possible key(s) of length 33:
really long s3cr3t k3y... PADDING
</pre>

所以，如果自动解密失败了，你可以这样验证：

- (-m) max length to try longer keys
- (-l) selected length to see some interesting keys
- (-c) the most frequent char to produce right plaintext

Author: hellman ( hellman1908@gmail.com )

License: MIT License (opensource.org/licenses/MIT)
