# Lab 5 - Hash Functions
## Performance report
### Hardware specifications
| Hardware | Specification |
| --- | --- |
| CPU | Intel Core i5-8300H CPU @ 2.30 GHz |
| RAM | 16.0 GB |
### Parameters
| Parameter | Value |
|---|---|
| message | `Nguyễn Đạt Thịnh - 19520982` |

## Performance
| Hash function | Average execution time on Windows (ms) | Average execution time on Linux (ms) |
|---|---|---|
| SHA224 | `0.0005` | `0.0008872` |
| SHA256 | `0.0004` | `0.0009016` |
| SHA384 | `0.0006` | `0.0009678` |
| SHA512 | `0.0005` | `0.000964` |
| SHA3-224 | `0.0007` | `0.0010582` |
| SHA3-256 | `0.0009` | `0.0010926` |
| SHA3-384 | `0.0006` | `0.0010705` |
| SHA3-512 | `0.0009` | `0.0011068` |
| SHAKE128 *(with digest size = 32 bytes)* | `0.0006` | `0.0010564` |
| SHAKE256 *(with digest size = 32 bytes)* | `0.0007` | `0.0010667` |

# Lab 6 - MD5 Collision attack
## Task 1: Generate 2 different files with the same MD5 hash
Prefix file:  
```
└─$ cat prefix.txt
Nguyen Dat Thinh
19520982
ANTN2019

Lab 6: MD5 collision attack
```  

File size: 64 bytes.  
```
└─$ ls -l prefix.txt
-rwxrwxrwx 1 datthinh datthinh      64 Jun 23 15:27 prefix.txt
```  

Run the tool `md5collgen` to create 2 different files with the same prefix and the same MD5 hash digest.  
```
└─$ ./md5collgen -p ./prefix.txt -o out1.bin out2.bin
MD5 collision generator v1.5
by Marc Stevens (http://www.win.tue.nl/hashclash/)

Using output filenames: 'out1.bin' and 'out2.bin'
Using prefixfile: './prefix.txt'
Using initial value: 241e428bd0199dd43845ed4010c23327

Generating first block: ..........
Generating second block: S00..............
Running time: 10.228 s
```

Compare the two out files.  

`out1.bin`:  
```
└─$ xxd out1.bin
00000000: 4e67 7579 656e 2044 6174 2054 6869 6e68  Nguyen Dat Thinh
00000010: 0a31 3935 3230 3938 320a 414e 544e 3230  .19520982.ANTN20
00000020: 3139 0a0a 4c61 6220 363a 204d 4435 2063  19..Lab 6: MD5 c
00000030: 6f6c 6c69 7369 6f6e 2061 7474 6163 6b0a  ollision attack.
00000040: 1b5c b015 8d4f d77f 77c8 62a2 12dd 72ad  .\...O..w.b...r.
00000050: 4d2d 5276 006c 1504 62d2 4056 6ef8 a30a  M-Rv.l..b.@Vn...
00000060: bfdc cac6 58f4 13fe 4b4a 61a3 c98d 5764  ....X...KJa...Wd
00000070: 5e04 e667 7cc5 ae67 0686 8581 4ebc da8f  ^..g|..g....N...
00000080: 634f 79ce 13ff 41b3 cd1b 4d4d 376c 7e99  cOy...A...MM7l~.
00000090: 9ed6 f14a 1676 8121 c957 f8c4 591a 5d32  ...J.v.!.W..Y.]2
000000a0: 895f d7f9 39f6 8270 ab47 cc0f cb51 76a6  ._..9..p.G...Qv.
000000b0: dd73 c835 4488 dbeb 394e 1d5b 5ef1 721f  .s.5D...9N.[^.r.
```

`out2.bin`:  
```
└─$ xxd out2.bin
00000000: 4e67 7579 656e 2044 6174 2054 6869 6e68  Nguyen Dat Thinh
00000010: 0a31 3935 3230 3938 320a 414e 544e 3230  .19520982.ANTN20
00000020: 3139 0a0a 4c61 6220 363a 204d 4435 2063  19..Lab 6: MD5 c
00000030: 6f6c 6c69 7369 6f6e 2061 7474 6163 6b0a  ollision attack.
00000040: 1b5c b015 8d4f d77f 77c8 62a2 12dd 72ad  .\...O..w.b...r.
00000050: 4d2d 52f6 006c 1504 62d2 4056 6ef8 a30a  M-R..l..b.@Vn...
00000060: bfdc cac6 58f4 13fe 4b4a 61a3 c90d 5864  ....X...KJa...Xd
00000070: 5e04 e667 7cc5 ae67 0686 8501 4ebc da8f  ^..g|..g....N...
00000080: 634f 79ce 13ff 41b3 cd1b 4d4d 376c 7e99  cOy...A...MM7l~.
00000090: 9ed6 f1ca 1676 8121 c957 f8c4 591a 5d32  .....v.!.W..Y.]2
000000a0: 895f d7f9 39f6 8270 ab47 cc0f cbd1 75a6  ._..9..p.G....u.
000000b0: dd73 c835 4488 dbeb 394e 1ddb 5ef1 721f  .s.5D...9N..^.r.
```  

The 2 files have the same prefix but different suffix. Now compute their hashes:  
```
└─$ md5sum out1.bin out2.bin
7394eb7949b776f98bdece091c18fff1  out1.bin
7394eb7949b776f98bdece091c18fff1  out2.bin
```  
> Their hashes are the same! COLLISION 💥  

## Task 2: Two different executable files having the same MD5 hash
This is my program.  
```c
#include <stdio.h>

unsigned char xyz[200] = {
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
};

int main()
{
        int i = 0;
        for (i=0; i<200; i++) {
                printf("%x", xyz[i]);
        }
        printf("\n");
}
```  
> Choosing an array of 200 identical characters makes it easier to spot this array in binary file.  

After compiling the above program, I can see where the array resides.  
```
00003020: 4610 0000 0000 0000 0000 0000 0000 0000  F...............
00003030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00003040: 0000 0000 0000 0000 4840 0000 0000 0000  ........H@......
00003050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00003060: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00003070: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00003080: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00003090: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
000030a0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
000030b0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
000030c0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
000030d0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
000030e0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
000030f0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00003100: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00003110: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00003120: 4141 4141 4141 4141 4743 433a 2028 4465  AAAAAAAAGCC: (De
00003130: 6269 616e 2031 302e 322e 312d 3629 2031  bian 10.2.1-6) 1
00003140: 302e 322e 3120 3230 3231 3031 3130 0000  0.2.1 20210110..
00003150: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00003160: 0000 0000 0000 0000 0000 0000 0300 0100  ................
00003170: a802 0000 0000 0000 0000 0000 0000 0000  ................
00003180: 0000 0000 0300 0200 c402 0000 0000 0000  ................
```

### Idea
The idea behind this attack is as follows:
![image](https://user-images.githubusercontent.com/44528004/123081570-4842c000-d448-11eb-8bc0-9ece03e78060.png)  

First, I separate the executable file into 3 parts.  
- The first part, called the **prefix**, starts at the beginning of the file to somewhere in the middle of the array `xyz`. In this case, I truncate the first `0x3070` bytes of the executable file, which is up to the first 16 `A` characters of the array.  
- The second part, in which I will find a hash collision on, is a portion of the array.  
- The last part, called the **suffix**, continues at the remaining portion of the array `xyz` to the end of the file.  

Second, I find a collision with that **prefix**.  

Third, I append the remaining part (the **suffix**) of the original file to the 2 new files having collision.

#### Truncate the prefix
I will truncate the original file up to `0x3070` bytes which also cuts the first 16 bytes of the array `xyz`.  
As `0x3070` is equivalent to `12400` bytes. The following command will truncate `12400` bytes of the executable file and store these bytes to the file called `prefix`.  
```
head -c 12400 program > prefix
```
> Here, `program` is the name of the executable file.  

#### Find a collision
With the prefix, I can find a collision with the following command:  
```
./md5collgen -p prefix -o coll_prefix_1 coll_prefix_2
```  

Here is the binary representation of last part of these output files.  
```
# coll_prefix_1
00003060: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00003070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00003080: 44c8 8084 8f84 1d6f 7768 4c21 9baf 6251  D......owhL!..bQ
00003090: 074c aad5 8458 082a 6166 7922 e596 06e9  .L...X.*afy"....
000030a0: 92dd ac0b e04c f6c8 eb0f c3f4 b77d ac5b  .....L.......}.[
000030b0: eab0 4440 1aa8 645f 53d9 fa71 68e1 0abe  ..D@..d_S..qh...
000030c0: 5dc9 f4c6 df2d 21ca 625a c715 7009 457e  ]....-!.bZ..p.E~
000030d0: dbae eba8 5714 bded 2ae5 b217 ca77 456e  ....W...*....wEn
000030e0: 5dc0 fa15 eb33 cfc7 c268 f931 8534 8fff  ]....3...h.1.4..
000030f0: eb90 a39b 4ebf 330e a79f a1e7 eec2 3ce1  ....N.3.......<.
```  
```
# coll_prefix_2
00003060: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00003070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00003080: 44c8 8084 8f84 1d6f 7768 4c21 9baf 6251  D......owhL!..bQ
00003090: 074c aa55 8458 082a 6166 7922 e596 06e9  .L.U.X.*afy"....
000030a0: 92dd ac0b e04c f6c8 eb0f c3f4 b7fd ac5b  .....L.........[
000030b0: eab0 4440 1aa8 645f 53d9 faf1 68e1 0abe  ..D@..d_S...h...
000030c0: 5dc9 f4c6 df2d 21ca 625a c715 7009 457e  ]....-!.bZ..p.E~
000030d0: dbae eb28 5714 bded 2ae5 b217 ca77 456e  ...(W...*....wEn
000030e0: 5dc0 fa15 eb33 cfc7 c268 f931 85b4 8eff  ]....3...h.1....
000030f0: eb90 a39b 4ebf 330e a79f a167 eec2 3ce1  ....N.3....g..<.
```  

These files seem identical but they are indeed different.  
```
└─$ diff coll_prefix_1 coll_prefix_2
Binary files coll_prefix_1 and coll_prefix_2 differ
```  

Let's see their MD5 hashes.  
```
└─$ md5sum coll_prefix_1 coll_prefix_2
1a2aa7a8215eb20f7a5b426f1e2a95fc  coll_prefix_1
1a2aa7a8215eb20f7a5b426f1e2a95fc  coll_prefix_2
```  
> Their hashes are identical!  

#### Append the suffix to the collision
So far, I already have 2 md5hash-identical executable files whose sizes are `12544` bytes.  
```
-rwxrwxrwx 1 datthinh datthinh   12544 Jun 23 17:17 coll_prefix_1
-rwxrwxrwx 1 datthinh datthinh   12544 Jun 23 17:17 coll_prefix_2
```

My original executable file `program` has the size of `16928` bytes.  
```
-rwxrwxrwx 1 datthinh datthinh   16928 Jun 23 16:57 program
```  

So I need to extract the last `16928 - 12544 = 4384` bytes from the original executable file and append these bytes to the collision files.  
```
# extract the suffix
tail -c 4384 program > suffix

# copy collision files for later readability
cp coll_prefix_1 program1
cp coll_prefix_2 program2

# append suffix to program1, and program2
cat suffix >> program1
cat suffix >> program2
```  

Now I have the 2 new programs having the same size of the original one.  
```
-rwxrwxrwx 1 datthinh datthinh   16928 Jun 23 16:57 program
-rwxrwxrwx 1 datthinh datthinh   16928 Jun 23 17:24 program1
-rwxrwxrwx 1 datthinh datthinh   16928 Jun 23 17:24 program2
```  

Let's compute hashes of `program1` and `program2` to see if they are identical.  
```
└─$ md5sum program1 program2
c24d50132e27dc7020ec80c158093fb2  program1
c24d50132e27dc7020ec80c158093fb2  program2
```
> Identical!  

Let I check their different-ness with `diff`.  
```
└─$ diff program1 program2
Binary files program1 and program2 differ
```  
> These files are different!

Let's execute them to see if their behavior is the same.  
```
└─$ ./program1
41414141414141414141414141414141000000000000000044c880848f841d6f77684c219baf625174caad5845882a61667922e5966e992ddacbe04cf6c8ebfc3f4b77dac5beab044401aa8645f53d9fa7168e1abe5dc9f4c6df2d21ca625ac715709457edbaeeba85714bded2ae5b217ca77456e5dc0fa15eb33cfc7c268f93185348fffeb90a39b4ebf33ea79fa1e7eec23ce141414141414141414141414141414141414141414141414141414141414141414141414141414141

└─$ ./program2
41414141414141414141414141414141000000000000000044c880848f841d6f77684c219baf625174caa55845882a61667922e5966e992ddacbe04cf6c8ebfc3f4b7fdac5beab044401aa8645f53d9faf168e1abe5dc9f4c6df2d21ca625ac715709457edbaeeb285714bded2ae5b217ca77456e5dc0fa15eb33cfc7c268f93185b48effeb90a39b4ebf33ea79fa167eec23ce141414141414141414141414141414141414141414141414141414141414141414141414141414141
```
Their outputs are slightly different.  
> So these 2 programs are different but having the same MD5 hash. COLLISION 💥  

## Task 3: Chosen-prefix collisions attack
First source code:  
```c
// say_hi.c
#include <stdio.h>
int main()
{
        printf("Hi");
}
```  

Second source code:  
```c
// say_hello.c
#include <stdio.h>
int main()
{
        printf("Hello");
}
```  

Compile the two source codes and check their md5 hashes.  
```
└─$ gcc say_hi.c -o say_hi
└─$ gcc say_hello.c -o say_hello
```  

Let's execute these files.  
```
└─$ ./say_hi
Hi
└─$ ./say_hello
Hello
```  
> Their behaviors are completely different.  

Let's compare their hashes.  
```
└─$ md5sum say_hi say_hello
05ad29fc8e10e98158c6e5713f34cc56  say_hi
dfa85087656480d1d6891c24c6af7885  say_hello
```  
> Their md5 hashes are different.  

Run `hashclash` tool to make these 2 executable files collide.  
```
└─$ ./../cpc.sh ./say_hi ./say_hello
```  

When the tool is done, we have 2 files with an extension `.coll`.  
```
└─$ ls -l say_hello.coll say_hi.coll
-rwxrwxrwx 1 datthinh datthinh 17088 Jun  23 18:02 say_hello.coll
-rwxrwxrwx 1 datthinh datthinh 17088 Jun  23 18:02 say_hi.coll
```  

Let's execute them.  
```
└─$ ./say_hello.coll
Hello
└─$ ./say_hi.coll
Hi
```  

They still act as our original programs, but this time, let's compare their md5 hashes.  
```
└─$ md5sum say_hello.coll say_hi.coll
75aa2ceb33367c14812be9c97f3a44b9  say_hello.coll
75aa2ceb33367c14812be9c97f3a44b9  say_hi.coll
```  
> Their hashes new are identical. COLLISION 💥


