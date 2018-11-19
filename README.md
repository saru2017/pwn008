# PWNオーバーフロー入門: 64bit環境でのROPコード (SSP、ASLR、PIE無効で64bit ELF)

## はじめに

PWNオーバーフローを勉強し始めたのは実は[SECCON 2018 Online CTF](https://score-quals.seccon.jp/)の[SECCON 2018 Online CTF](https://score-quals.seccon.jp/challenges#Classic%20Pwn)を解きたかったから。
write upを読んでもなんとなくにしか分からず、せっかくの機会だから勉強してみようかと。
と思ったら思いのほか難しく．．．長かった．．．

## まずはいろいろ調べる

提供されているのは

- classic_aa9e979fd5c597526ef30c003bffee474b314e22
- libc-2.23.so_56d992a0342a67a887b8dcaae381d2cc51205253

の2つ。
これはclassicというプログラムとlibc-2.23.soというライブラリなので

- classic
- libc-2.23.so

に名前変更。

classicに実行権限を与えて実行してみる。

```bash-statement
saru@lucifen:~/pwn008$ ./classic
Classic Pwnable Challenge
Local Buffer >> hello
Have a nice pwn!!
saru@lucifen:~/pwn008$
```

文字列を受け取って「```Have a nice pwn!!```」を表示するプログラム。

### checksec

checksecを実行

```
saru@lucifen:~/pwn008$ checksec --file classic
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   classic

saru@lucifen:~/pwn008$
```
SSPは無効、NXは有効、PIEは無効。

### ldd

リンクしているライブラリをチェック

```
saru@lucifen:~/pwn008$ LD_LIBRARY_PATH=. ldd ./classic
        linux-vdso.so.1 (0x00007ffff7ffa000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff79e4000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffff7dd5000)
saru@lucifen:~/pwn008$
```

残念ながらバージョンが違う。
が、

```python
base_libc = 0x00007ffff79e4000
```

ということ？

```
saru@lucifen:~/pwn008$ ls -l /lib/x86_64-linux-gnu/libc.so.6
lrwxrwxrwx 1 root root 12 Apr 16  2018 /lib/x86_64-linux-gnu/libc.so.6 -> libc-2.27.so
saru@lucifen:~/pwn008$
```

とりあえず自サーバのやつでシェル取った後にアドレスだけ書き換えるというアプローチで行ってみよう。

### file

ファイルの種類をチェック

```
saru@lucifen:~/pwn008$ file classic
classic: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a8a02d460f97f6ff0fb4711f5eb207d4a1b41ed8, not stripped
saru@lucifen:~/pwn008$
```

64 bit ELFなので未経験。

### gdb-peda

#### info proc mapping

```
gdb-peda$ info proc mapping
process 11509
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x401000     0x1000        0x0 /home/saru/pwn008/classic
            0x600000           0x601000     0x1000        0x0 /home/saru/pwn008/classic
            0x601000           0x602000     0x1000     0x1000 /home/saru/pwn008/classic
      0x7ffff79e4000     0x7ffff7bcb000   0x1e7000        0x0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7bcb000     0x7ffff7dcb000   0x200000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcb000     0x7ffff7dcf000     0x4000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dcf000     0x7ffff7dd1000     0x2000   0x1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7ffff7dd1000     0x7ffff7dd5000     0x4000        0x0
      0x7ffff7dd5000     0x7ffff7dfc000    0x27000        0x0 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7ffff7feb000     0x7ffff7fed000     0x2000        0x0
      0x7ffff7ff7000     0x7ffff7ffa000     0x3000        0x0 [vvar]
      0x7ffff7ffa000     0x7ffff7ffc000     0x2000        0x0 [vdso]
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x27000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x28000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
gdb-peda$
```

```python
base_libc = 0x00007ffff79e4000
```

はあってそう。

#### ざっと実行して行く

1. puts
2. printf 
3. gets
4. puts

getsの脆弱性を利用しよう。

#### getsでオーバフローさせてみる

使う文字列は以下の30バイトを試す。

```
abcdefghijABCDEFGHIJ1234567890
```

エラー起きず。
次は60バイト

```
abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890
```

エラー起きず。
次は90バイト。

```
abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890
```
Segmentation faultで落ちるもののHave a nice pwn!!ということはputsまで行っちゃってるのでリターンアドレスは書き換えられてない気がする。

```
Have a nice pwn!!

Program received signal SIGSEGV, Segmentation fault.
0x00000000004006e6 in main ()
```

120バイトも試してみる。
```
abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890
```

```
Have a nice pwn!!

Program received signal SIGSEGV, Segmentation fault.
0x00000000004006e6 in main ()
```

変わらず．．．

次は240バイト。

```
abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890
```

```
[-------------------------------------code-------------------------------------]
   0x4006db <main+50>:  call   0x400520 <puts@plt>
   0x4006e0 <main+55>:  mov    eax,0x0
   0x4006e5 <main+60>:  leave
=> 0x4006e6 <main+61>:  ret
   0x4006e7:    nop    WORD PTR [rax+rax*1+0x0]
   0x4006f0 <__libc_csu_init>:  push   r15
   0x4006f2 <__libc_csu_init+2>:        push   r14
   0x4006f4 <__libc_csu_init+4>:        mov    r15d,edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3a8 ("CDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890")
0008| 0x7fffffffe3b0 ("1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890")
0016| 0x7fffffffe3b8 ("90abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890")
0024| 0x7fffffffe3c0 ("ghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890")
0032| 0x7fffffffe3c8 ("EFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890")
0040| 0x7fffffffe3d0 ("34567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890")
0048| 0x7fffffffe3d8 ("abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890")
0056| 0x7fffffffe3e0 ("ijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004006e6 in main ()
```

ようやくHave a nice pawn!!が出なくなった。

120
abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890

130

abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ


150

abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890


90バイト。

```
abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890
```

```
[-------------------------------------code-------------------------------------]
   0x4006db <main+50>:  call   0x400520 <puts@plt>
   0x4006e0 <main+55>:  mov    eax,0x0
   0x4006e5 <main+60>:  leave
=> 0x4006e6 <main+61>:  ret
   0x4006e7:    nop    WORD PTR [rax+rax*1+0x0]
   0x4006f0 <__libc_csu_init>:  push   r15
   0x4006f2 <__libc_csu_init+2>:        push   r14
   0x4006f4 <__libc_csu_init+4>:        mov    r15d,edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3a8 ("CDEFGHIJ1234567890")
0008| 0x7fffffffe3b0 ("1234567890")
0016| 0x7fffffffe3b8 --> 0x7fffff003039
0024| 0x7fffffffe3c0 --> 0x100000000
0032| 0x7fffffffe3c8 --> 0x4006a9 (<main>:      push   rbp)
0040| 0x7fffffffe3d0 --> 0x0
0048| 0x7fffffffe3d8 --> 0x3017526ccfe7b43e
0056| 0x7fffffffe3e0 --> 0x400580 (<_start>:    xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004006e6 in main ()
```

80バイトで起こせてる気がする。

```
abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ1234567890abcdefghijABCDEFGHIJ
```

73～80バイト目で書き換えられてそう。

念のため

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAabcdefgh
```

うまく落ちてる。gdbだと0x7fffffffe3a8にmainのreturn addressが書かれているっぽい。

書き換えなきゃいけないのはgetsのreturn addressじゃなくてmainのreturn addressだからHave a nice pawnは表示されて良いのか。

### system関数の呼び方

さて次に調べなきゃいけないのはなんだ？

64bitでのsystem関数の呼び方か。

残念ながらアセンブラ読んだりしたけど分からない．．．

少しだけカンニング。

[SECCON 2018 Online CTF Writeup Pwn:classic - Qiita](https://qiita.com/GmS944y/items/4821a631a6d34b54ab8d)

なるほど．．．

32bitと64bitでは関数の呼び出し方が変わっているのがポイントっぽい。
32bitでの関数呼び出しはスタックに引数を詰んでいたのだが、64bitではレジスタに渡すとのこと。
32bitでもシステムコールはeax、ebx、ecxとかで渡すのと同じ感じか。
調べてみるとよりわかりやすい情報発見。

[x64の関数呼び出し - Qiita](https://qiita.com/FAMASoon/items/a93c1361f80bb28f895c)

1. rdi
2. rsi
3. rdx
4. rcx
5. r8
6. r9

を使う。
つまりスタックに`/bin/sh`を書いて単純にsystem関数をlibcから呼び出すだけじゃだめで、`/bin/sh`のアドレスを一旦rdiに書き込む仕組みが必要。
そこでlibc内、もしくはclassic内のgadget`pop rdi, ret`を使えば良いのだろう。

が、そんなものない様子．．．

```objdump -d -M intel libc-2.23.so | grep -B1 ret | grep -A1 pop```

もう一回カンニング。

[SECCON 2018 Online CTF Writeup Pwn:classic - Qiita](https://qiita.com/GmS944y/items/4821a631a6d34b54ab8d)

ちゃんとgadget`pop rdi, ret`見つけられてる．．．
なんで？？

と思って調べてたらどうやらrp-lin-x64というツールを使っている様子．．．
ダウンロードして実行権限与えて使ってみると

```
saru@lucifen:~/pwn008$ curl -L https://github.com/downloads/0vercl0k/rp/rp-lin-x64 > rp-lin-x64
saru@lucifen:~/pwn008$ chmod 755 rp-lin-x64
saru@lucifen:~/pwn008$ ./rp-lin-x64 --file=./classic --rop=1 --unique | grep pop
0x00400752: pop r15 ; ret  ;  (1 found)
0x004005e0: pop rbp ; ret  ;  (3 found)
0x00400753: pop rdi ; ret  ;  (1 found)
saru@lucifen:~/pwn008$
```

なんと．．．
見つかった。
しかも0x00400753という変なアドレス．．．
バイナリを無理やりgadgetとして使うイメージなんだろうか。

rdi`/bin/sh`にアドレス放り込んで、retでsystemに飛ばす感じなのでスタックには

[pop rdiのアドレス]
[/bin/shのアドレス]
[systemのアドレス]

を書き込んでやれば行けるはず。

### おわりに

ここまでカンニングしつつやっててわかったのがGOT利用してALSR有効時の対応方法学ばないとだめなのでこれはここで一回終了して32bitでALSR回避を次にやります．．．
