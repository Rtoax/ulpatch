
## 代码风格

请参考 [Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html) 来撰写 C 代码。可能 Linux 内核文档的不同版本文档有稍许差异，比如 [Linux 4.19](https://www.kernel.org/doc/html/v4.10/process/coding-style.html)，但是差别不会很大

你可以使用 `indent` 来修改你的代码：

```bash
# 输出到stdout
$ indent --linux-style -st main.c
# 或者直接覆盖main.c
$ indent --linux-style main.c
```


## VIM 配置

vim 的基础配置 `.vimrc` 文件需要包含如下内容：

```
set tabstop=8
set softtabstop=8
set shiftwidth=8
set cc=80
```


## 代码文件格式

ULPatch 使用 **Unix format** 而不是 **DOS or Mac format**。

正如你可以通过 `dos2unix(1)` 手册看到的：

> In DOS/Windows text files a line break, also known as newline, is a combination of two characters: a Carriage Return (CR) followed by a Line Feed (LF). In Unix text files a line break is a single character: the Line Feed (LF). In Mac text files, prior to Mac OS X, a line break was single Carriage Return (CR) character. Nowadays Mac OS uses Unix style (LF) line breaks.

如果你的文件是 **DOS or Mac format**，你可能经常在 UNIX 下看到源代码行尾存在`^M`。


## 编程标准

- 不要使用 `%s`+`strerror(errno)` 的方式打印错误信息，而是使用`%m`。
- 记住，在必要的时候，在函数中设置`errno`。


## 文档标准

- 同时修改中文和英文文档；
- 中文文档中的英文单词，需要与中文之间用**空格**分隔；

