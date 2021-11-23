# nqdumpgo

_A tool coded by GO to decode cryptoed netease music files and qqmusic files_
_一个使用 Go 语言编写的用于解密被网易云音乐或 QQ 音乐加密的文件的程序,Go 程序在拥有与 C++程序相近的效率的同时,大大方便了程序的跨平台编译,有计划写多线程并行转换加密文件的程序_

---

##### This project depends on third-party libraries

##### 本项目依赖第三方 Go 库,编译前先下载依赖

** Instructions **
** 使用方法 **

** On Windows **

### 在 Windows 10 和 Ubuntu 20.04 下使用 Go v17 成功编译运行,编译命令相同

```
##### 编译程序
###### 在编译之前需要下载第三方库
> go get nqdumpgo
##### 一键编译
> go build nqdumpgo
##### 编译完成
> 在Windows下生成的二进制文件为nqdumpgo.exe, 在Linux下生成的二进制文件为nqdumpgo
```

### 使用教程

** On Windows **

> 图形界面:
> 将要解密的文件拖放到 nqdumpgo.exe 上即可自动解密,可使用  
> nqdumpgo.exe <inputfile1> <inputfile2> <...>
> 的格式来逐项解密多个音乐文件,可以是不同格式的文件
>
> 命令行界面和 Linux 几乎无异,一样可以使用通配符 \*

** On Linux **

> 命令行:
> nqdumpgo <inputfile1> <inputfile2> <...>
> 可使用 nqdumpgo /home/crmmc/music/\* 的格式来逐项解密多个音乐文件,可以是不同格式的文件

---

** Porject Used code from other github projects **  
** 本项目使用了来自其他 Github 项目的部分代码,十分感谢代码作者的无私开源,让我不用重复造轮子 **  
https://github.com/lucifer9/qmcdump-go

https://github.com/ljm12914/ncmdump

https://github.com/unlock-music/unlock-music

---

CRMMC ---- KGDsave Software Studio
