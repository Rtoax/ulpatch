
## Coding Style

Please refer to [Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html) for the coding style of C language. There may be some differences in specific Linux kernel versions, such as [Linux 4.19](https://www.kernel.org/doc/html/v4.10/process/coding-style.html), but overall it won't change much.


## VIM Config

The basic configuration of the `.vimrc` file is as follows:

```
set tabstop=8
set softtabstop=8
set shiftwidth=8
set cc=80
```


## Code File Format

ULPatch use **Unix format** not **DOS or Mac format**.

As you can see from manual of `dos2unix(1)`

> In DOS/Windows text files a line break, also known as newline, is a combination of two characters: a Carriage Return (CR) followed by a Line Feed (LF). In Unix text files a line break is a single character: the Line Feed (LF). In Mac text files, prior to Mac OS X, a line break was single Carriage Return (CR) character. Nowadays Mac OS uses Unix style (LF) line breaks.

You may often see the special character `^M` under Unix like system if code is **DOS or Mac format**.


## Programming Standards

- Never use `%s`+`strerror(errno)` display string describing error number in log, use `%m` instead.

