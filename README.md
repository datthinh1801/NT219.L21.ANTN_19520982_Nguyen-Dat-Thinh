# [Cryptology] Lab 1, 2
This repository belongs to my cryptology's schoolwork which relates to the implementation of block cipher encryption algorithms such as DES, AES.  

# Performance report
## Lab 1
### DES
| Parameter | Value |
|---|---|
| Plaintext | `Nguyễn Đạt Thịnh - 19520982 - ANTN2019 - DES`|
| Key | `C5C4977837225004`|
| IV  | `B3A582FFA5D0D483`|
|Number of iteration| `10000` |


| Scheme | Mode | Average encryption time | Average decryption time |
|---|---|---|---|
| DES | ECB | `0.0039` ms | `0.0041` ms |
| DES | CBC | `0.0038` ms | `0.0041` ms |
| DES | CFB | `0.0041` ms | `0.0038` ms |
| DES | OFB | `0.0040` ms | `0.0044` ms |
| DES | CTR | `0.0048` ms | `0.0040` ms |

### AES
| Parameter | Value |
|---|---|
| Plaintext | `Nguyễn Đạt Thịnh - 19520982 - ANTN2019 - AES`|
| Key  | `2D98861304954560D84377097097DA026A871531F7DCE87F8012358CC988D575`|
| IV | `DF638B3CB0A1D57BD5AEA11BA2351E3E`|
| IV (8 bytes - CCM) | `DF638B3CB0A1D57B` |
| Authenticated data | `19520982` |
|Number of iteration| `10000` |  

| Scheme | Mode | Average encryption time | Average decryption time |
|---|---|---|---|
| AES | ECB | `0.0018` ms | `0.0018` ms |
| AES | CBC | `0.0020` ms | `0.0021` ms |
| AES | CFB | `0.0024` ms | `0.0020` ms |
| AES | OFB | `0.0025` ms | `0.0021` ms |
| AES | CTR | `0.0016` ms | `0.0024` ms |
| AES | XTS | `0.0026` ms | `0.0025` ms |
| AES | GCM | `0.0026` ms | `0.0041` ms |
| AES | CCM | `0.0026` ms | `0.0046` ms |
## Lab 2
