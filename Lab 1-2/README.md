# Performance report
### Hardware specifications
| Hardware | Specification |
| --- | --- |
| CPU | Intel Core i5-8300H CPU @ 2.30 GHz |
| RAM | 16.0 GB |

### DES
| Parameter | Value |
|---|---|
| Plaintext | `Nguyễn Đạt Thịnh - 19520982 - ANTN2019 - DES`|
| Key | `C5C4977837225004`|
| IV  | `B3A582FFA5D0D483`|
|Number of iteration| `10000` |


| Scheme | Mode | Average encryption time (Windows) | Average decryption time (Windows) | Average encryption time (Linux) | Average decryption time (Linux) |
|---|---|---|---|---|---|
| DES | ECB | `0.0039` ms | `0.0041` ms | `0.0042327` ms | `0.0043001` ms |
| DES | CBC | `0.0038` ms | `0.0041` ms | `0.004524` ms | `0.004445` ms |
| DES | CFB | `0.0041` ms | `0.0038` ms | `0.003743` ms | `0.003742` ms |
| DES | OFB | `0.0040` ms | `0.0044` ms | `0.0047278` ms | `0.0047475` ms |
| DES | CTR | `0.0048` ms | `0.0040` ms | `0.0049443` ms | `0.0049053` ms |

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
| AES | ECB | `0.0018` ms | `0.0018` ms | `0.0016519` ms | `0.001711` ms |
| AES | CBC | `0.0020` ms | `0.0021` ms | `0.0016284` ms | `0.0016791` ms |
| AES | CFB | `0.0024` ms | `0.0020` ms | `0.0021156` ms | `0.002061` ms |
| AES | OFB | `0.0025` ms | `0.0021` ms | `0.0020815` ms | `0.0020811` ms |
| AES | CTR | `0.0016` ms | `0.0024` ms | `0.0016198` ms | `0.0015727` ms |
| AES | XTS | `0.0026` ms | `0.0025` ms | `0.0018335` ms | `0.0019169` ms |
| AES | GCM | `0.0026` ms | `0.0041` ms | `0.0018834` ms | `0.0028637` ms |
| AES | CCM | `0.0026` ms | `0.0046` ms | `0.0022685` ms | `0.0034277` ms |
