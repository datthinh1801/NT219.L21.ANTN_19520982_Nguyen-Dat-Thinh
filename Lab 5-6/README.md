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
| Hash function | Average execution time (ms) |
|---|---|
| SHA224 | `0.0005` |
| SHA256 | `0.0004` |
| SHA384 | `0.0006` |
| SHA512 | `0.0005` |
| SHA3-224 | `0.0007` |
| SHA3-256 | `0.0009` |
| SHA3-384 | `0.0006` |
| SHA3-512 | `0.0009` |
| SHAKE128 *(with digest size = 32 bytes)* | `0.0006` |
| SHAKE256 *(with digest size = 32 bytes)* | `0.0007` |  

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
00000040: d910 bf82 fd62 e883 5880 a71c 69ba 6827  .....b..X...i.h'
00000050: 90d0 547a fc9d 7829 4e06 404e 6f20 8d09  ..Tz..x)N.@No ..
00000060: d0e5 aecc d04c e8c5 6f10 d992 d7ab f21a  .....L..o.......
00000070: 832d c665 cf24 0592 9819 025a 1858 4d7b  .-.e.$.....Z.XM{
00000080: fb59 fede 1028 272a 8124 9db7 a171 443f  .Y...('*.$...qD?
00000090: 5e67 844e 14ba e059 cdbb f6c4 5922 591e  ^g.N...Y....Y"Y.
000000a0: 4f33 d6f9 2bd9 8682 cb68 c1cf 8496 6bca  O3..+....h....k.
000000b0: c2c4 ab8d d87d aa33 bed6 645b b3e9 cf4b  .....}.3..d[...K
```

`out2.bin`:  
```
└─$ xxd out2.bin
00000000: 4e67 7579 656e 2044 6174 2054 6869 6e68  Nguyen Dat Thinh
00000010: 0a31 3935 3230 3938 320a 414e 544e 3230  .19520982.ANTN20
00000020: 3139 0a0a 4c61 6220 363a 204d 4435 2063  19..Lab 6: MD5 c
00000030: 6f6c 6c69 7369 6f6e 2061 7474 6163 6b0a  ollision attack.
00000040: d910 bf82 fd62 e883 5880 a71c 69ba 6827  .....b..X...i.h'
00000050: 90d0 54fa fc9d 7829 4e06 404e 6f20 8d09  ..T...x)N.@No ..
00000060: d0e5 aecc d04c e8c5 6f10 d992 d72b f31a  .....L..o....+..
00000070: 832d c665 cf24 0592 9819 02da 1858 4d7b  .-.e.$.......XM{
00000080: fb59 fede 1028 272a 8124 9db7 a171 443f  .Y...('*.$...qD?
00000090: 5e67 84ce 14ba e059 cdbb f6c4 5922 591e  ^g.....Y....Y"Y.
000000a0: 4f33 d6f9 2bd9 8682 cb68 c1cf 8416 6bca  O3..+....h....k.
000000b0: c2c4 ab8d d87d aa33 bed6 64db b3e9 cf4b  .....}.3..d....K
```  

The 2 files have the same prefix but different suffix. Now compute their hashes:  
```
└─$ md5sum out1.bin
145222bca98e8d0aa596e244a490bf69  out1.bin
```
```
└─$ md5sum out2.bin
145222bca98e8d0aa596e244a490bf69  out2.bin
```  
> Their hashes are the same! COLLISION 💥

