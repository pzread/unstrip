unstrip
=======

ELF Unstrip Tool

Requirement
-----------
capstone python-binding https://github.com/aquynh/capstone  
pyelftools https://github.com/eliben/pyelftools  
python-sqlite  
python-msgpack  

Generate DB
-----------
1. Make sure the maximum file open limit >= 65536, since it will open lots of object files during generating db.
2. mkdir archobj
3. copy `<your .a files.> ex: libc.a, libpthread.a` to `archobj/`.
4. python2 unstrip.py gendb
5. The fingerprints will be stored in `fin.db`.

It's recommended to copy `libc.a` and `libpthread.a` to `archobj/`, they contain the basic object files for analysis.

Unstrip statically linked stripped binary
-----------------------------------------
1. python2 unstrip.py `<your binary>`
2. It will generate the unstripped binary named as `<your binary>.mark `

Future work
-----------
1. Greatly improve the matching methods.
2. Use symbolic execution to provide better basic block scan.

Demo
----
Source code, compile `gcc -static -s test.c -o test`
``` c
#include<stdio.h>
#include<stdlib.h>

int main(){
    puts("Hello world\n");
    system("ls");
    return 0;
}
```

objdump -d test
``` asm
...
40105e:       55                      push   %rbp
40105f:       48 89 e5                mov    %rsp,%rbp
401062:       bf 44 44 49 00          mov    $0x494444,%edi
401067:       e8 84 7b 00 00          callq  0x408bf0
40106c:       bf 51 44 49 00          mov    $0x494451,%edi
401071:       e8 3a 70 00 00          callq  0x4080b0
401076:       b8 00 00 00 00          mov    $0x0,%eax
40107b:       5d                      pop    %rbp
40107c:       c3                      retq
...
```

objdump -d test.mark
``` asm
...
000000000040105e <main>:
40105e:       55                      push   %rbp
40105f:       48 89 e5                mov    %rsp,%rbp
401062:       bf 44 44 49 00          mov    $0x494444,%edi
401067:       e8 84 7b 00 00          callq  408bf0 <puts>
40106c:       bf 51 44 49 00          mov    $0x494451,%edi
401071:       e8 3a 70 00 00          callq  4080b0 <system>
401076:       b8 00 00 00 00          mov    $0x0,%eax
40107b:       5d                      pop    %rbp
40107c:       c3                      retq
...
```
