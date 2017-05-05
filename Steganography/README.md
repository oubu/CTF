# 隐写术


## 图片

- 添加两张图片
- 异或字节（xor_bytes）
- 颜色加密

![](http://i.imgur.com/5IBxKbF.png)

___

## 命令行:

- 退出ffmpeg的音频:

```
$ ffmpeg -i windows.mp4 windows.wav
```


- 从视频中制作gif动画，使用 [ffmpeg](https://www.ffmpeg.org/download.html)

```sh
$ ffmpeg -i windows.mp4 windows.gif
```

- 处理图片的在线工具:
	* [utilitymill](http://utilitymill.com/utility/Steganography_Decode)
	* [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html)
	* [Paranoid.jar](https://ccrma.stanford.edu/~eberdahl/Projects/Paranoia/)


____

### 元数据


[Image metadata](http://regex.info/exif.cgi)

- 想要在一张图片中寻找信息，我们可以使用包 [pnginfo] 或 [pngcheck].

- 如果我们需要 [base64 解码] (例如一个带有图片的PGP键)。

- 奇怪的字块可能需要被XOR.

- 如果我们有一个解密的消息和一个密钥:
    1. 导入私钥以使用它来解密消息，使用：```gpg --allow-secret-key-import --import private.key```
    2. 解密，使用 ```gpg --decrypt message.pgp```.

- [ExifTool](http://www.sno.phy.queensu.ca/~phil/exiftool/index.html)


---

## 其他工具

- OpenStego
- OutGuess
- Gimp
- Audacity
- MP3Stego
- ffmpeg
- pngcheck
- StegFS
- Steghide






[Bacon's cipher]:http://en.wikipedia.org/wiki/Bacon's_ciphe
[Carpenter's Formula]:http://security.cs.pub.ro/hexcellents/wiki/writeups/asis_rsang
[pngcheck]: http://www.libpng.org/pub/png/apps/pngcheck.html
[karmadecay]: http://karmadecay.com/
[tineye]:  https://www.tineye.com/
[images.google.com]: https://images.google.com/?gws_rd=ssl
[base64 decoding]: http://www.motobit.com/util/base64-decoder-encoder.asp
[subbrute.py]: https://github.com/SparkleHearts/subbrute
[pnginfo]: http://www.stillhq.com/pngtools/
[namechk]: http://namechk.com

