# [Cryptology] Lab 1, 2
This repository belongs to my cryptology's schoolwork which relates to the implementation of block cipher encryption algorithms such as DES, AES.  

# Performance report
## Lab 1
### DES
| Parameter | Value |
|---|---|
| Plaintext | `Nguyễn Đạt Thịnh - 19520982 - ANTN2019 - DES`|
| Key (plaintext)| `Key DES!`|
| Key (hex) | `4B65792044455321`|
| IV (plaintext)| `IV DES~~`|
| IV (hex) | `4956204445537E7E`|
|Number of iteration| 10000|


| Scheme | Mode | Average encryption time | Average decryption time |
|---|---|---|---|
| DES | ECB | `0.0036` ms | `0.0035` ms |
| DES | CBC | `0.0043` ms | `0.0041` ms |
| DES | CFB | `0.0041` ms | `0.004` ms |
| DES | OFB | `0.0042` ms | `0.0035` ms |
| DES | CTR | `0.0042` ms | `0.0042` ms |
## Lab 2
