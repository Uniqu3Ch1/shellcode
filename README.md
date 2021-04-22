# shellcode项目
## 简介
个人shellcode练习项目</br>
主要功能：连接服务器并获取payload，创建线程执行payload。
payload使用[sRDI](https://github.com/monoxgas/sRDI)生成，理论上可以运行任何dll
## 原理
shellcode中字符串常量[编码](tools/str2intarr.exe)为int数组，并通过hash动态获取API。[hash工具](tools/gethash.exe)
## TODO：
优化数据传送逻辑