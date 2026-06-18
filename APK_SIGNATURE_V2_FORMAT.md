# APK Signature Scheme v2 Format

本文结合 ZIP/APK 文件结构说明 APK Signature Scheme v2 的签名格式，并说明本目录中
`apksig_v2_verify` 工具采用的外部证书校验策略。

## 1. APK 本质上是 ZIP

APK 文件本质是一个 ZIP archive。普通 ZIP 文件的主要结构如下：

```text
+---------------------------+
| Local File Header + Data   |
| Local File Header + Data   |
| ...                       |
+---------------------------+
| Central Directory          |
+---------------------------+
| End of Central Directory   |
| EOCD                       |
+---------------------------+
```

其中：

- `Local File Header + Data`：每个文件的实际内容。
- `Central Directory`：ZIP 的文件目录，记录每个 entry 的名字、属性、偏移等。
- `EOCD`：ZIP 结尾记录，包含 Central Directory 的偏移和大小。

EOCD 的 magic 是：

```text
50 4b 05 06
```

小端读取为：

```text
0x06054b50
```

EOCD 中有一个关键字段：

```text
offset 16: central directory offset, uint32 little-endian
```

APK v2 签名校验时会依赖这个字段定位 Central Directory。

## 2. APK v2 对 ZIP 结构的改造

APK Signature Scheme v2 在 ZIP 的 `Central Directory` 前插入一个 `APK Signing Block`。

加入 v2 签名后的 APK 结构如下：

```text
+--------------------------------+
| Local File Header + Data        |
| Local File Header + Data        |
| ...                            |
+--------------------------------+
| APK Signing Block               |
+--------------------------------+
| Central Directory               |
+--------------------------------+
| End of Central Directory        |
| EOCD                            |
+--------------------------------+
```

也就是说：

```text
APK Signing Block offset < Central Directory offset < EOCD offset
```

ZIP 原本并不知道 `APK Signing Block` 的存在。对 ZIP 来说，它只是 Central Directory 前的一段额外数据。

## 3. APK Signing Block 格式

APK Signing Block 的整体格式是：

```text
+-------------------------------+
| size of block, uint64 LE       |
+-------------------------------+
| ID-value pair                  |
| ID-value pair                  |
| ...                           |
+-------------------------------+
| size of block, uint64 LE       |
+-------------------------------+
| magic: "APK Sig Block 42"      |
+-------------------------------+
```

其中 magic 是 16 字节：

```text
41 50 4b 20 53 69 67 20 42 6c 6f 63 6b 20 34 32
```

ASCII 表示为：

```text
APK Sig Block 42
```

前后两个 `size of block` 必须相等。这个 size 不包含最前面的 8 字节 size 字段，但包含后面的 pair 区域、footer size 和 magic。

## 4. ID-value pair 格式

APK Signing Block 内部由多个 ID-value pair 组成：

```text
+-------------------------------+
| pair size, uint64 LE           |
+-------------------------------+
| ID, uint32 LE                  |
+-------------------------------+
| value, bytes                   |
+-------------------------------+
```

其中：

```text
pair size = 4 + value size
```

APK Signature Scheme v2 的 ID 是：

```text
0x7109871a
```

因此解析 APK v2 签名时，需要遍历 APK Signing Block 中的 ID-value pair，找到 ID 为 `0x7109871a` 的 value。

这个 value 就是 `APK Signature Scheme v2 block`。

## 5. APK Signature Scheme v2 Block 格式

v2 block 的顶层结构是 signer sequence：

```text
+--------------------------------+
| signers, length-prefixed bytes  |
+--------------------------------+
```

其中 `signers` 内部包含一个或多个 signer：

```text
+-------------------------------+
| signer, length-prefixed bytes  |
+-------------------------------+
| signer, length-prefixed bytes  |
+-------------------------------+
| ...                           |
+-------------------------------+
```

这里的 `length-prefixed bytes` 使用：

```text
+-------------------------------+
| length, uint32 LE              |
+-------------------------------+
| payload, bytes                 |
+-------------------------------+
```

## 6. Signer 格式

每个 signer 的格式是：

```text
+--------------------------------+
| signed data, length-prefixed    |
+--------------------------------+
| signatures, length-prefixed     |
+--------------------------------+
| public key, length-prefixed     |
+--------------------------------+
```

字段含义：

- `signed data`：被签名的数据，里面包含 content digests、证书和附加属性。
- `signatures`：一个或多个签名记录。
- `public key`：签名者的 SubjectPublicKeyInfo DER 编码。

APK v2 格式本身会把 signer 的 `public key` 放进签名块。基础格式校验可以使用这个
`public key` 验证 `signatures` 中的签名，签名覆盖的数据正是 `signed data`。

本项目的 `apksig_v2_verify` 工具额外要求输入一个外部可信证书，并使用外部证书中的
public key 进行验签。也就是说，工具不会单纯信任签名块里自带的 public key。

## 7. Signatures 格式

`signatures` 是一组 length-prefixed signature record：

```text
+--------------------------------+
| signature record, length-prefixed |
+--------------------------------+
| signature record, length-prefixed |
+--------------------------------+
| ...                            |
+--------------------------------+
```

每个 signature record：

```text
+-------------------------------+
| signature algorithm ID, uint32 |
+-------------------------------+
| signature, length-prefixed     |
+-------------------------------+
```

常见算法 ID：

| ID | Algorithm |
| --- | --- |
| `0x0101` | RSA-PSS with SHA-256 |
| `0x0102` | RSA-PSS with SHA-512 |
| `0x0103` | RSA-PKCS#1 v1.5 with SHA-256 |
| `0x0104` | RSA-PKCS#1 v1.5 with SHA-512 |
| `0x0201` | ECDSA with SHA-256 |
| `0x0202` | ECDSA with SHA-512 |
| `0x0301` | DSA with SHA-256 |

同一个 signer 可以包含多个签名算法。验证器通常会选择自己支持的最强算法进行验签。

## 8. Signed Data 格式

`signed data` 的格式是：

```text
+--------------------------------+
| digests, length-prefixed        |
+--------------------------------+
| certificates, length-prefixed   |
+--------------------------------+
| additional attributes, length-prefixed |
+--------------------------------+
```

### 8.1 Digests

`digests` 是一组 digest record：

```text
+--------------------------------+
| digest record, length-prefixed  |
+--------------------------------+
| digest record, length-prefixed  |
+--------------------------------+
| ...                            |
+--------------------------------+
```

每个 digest record：

```text
+-------------------------------+
| signature algorithm ID, uint32 |
+-------------------------------+
| digest, length-prefixed        |
+-------------------------------+
```

这里的 digest 是 APK 内容 digest。它不是简单地对整个 APK 文件做 SHA-256/SHA-512，而是按 APK v2 规则分块计算。

`digests` 中的 algorithm ID 顺序必须和 `signatures` 中的 algorithm ID 顺序一致。

### 8.2 Certificates

`certificates` 是一组 X.509 certificate：

```text
+--------------------------------+
| certificate, length-prefixed    |
+--------------------------------+
| certificate, length-prefixed    |
+--------------------------------+
| ...                            |
+--------------------------------+
```

每个 certificate 是 DER 编码。

校验时，signer 顶层的 `public key` 必须和第一张 certificate 中的 public key 一致。

注意：`certificates` 是证书列表，格式上允许包含多张 X.509 证书。但 APK 签名的应用身份
通常基于签名证书或签名 key 本身，不是浏览器 TLS 那种公共 CA 信任链模型。

### 8.3 Additional Attributes

`additional attributes` 是附加属性列表。基础 v2 校验可以解析但不一定使用这些属性。

## 9. APK 内容 digest 的覆盖范围

APK v2 的内容 digest 不覆盖 APK Signing Block 本身。

它覆盖三段数据：

```text
+--------------------------------+
| 1. APK Signing Block 之前的数据 |
+--------------------------------+
| APK Signing Block               |  <-- 不参与 digest
+--------------------------------+
| 2. Central Directory            |
+--------------------------------+
| 3. Modified EOCD                |
+--------------------------------+
```

对应为：

```text
content part 1 = apk[0 : signing_block_offset]
content part 2 = apk[central_directory_offset : eocd_offset]
content part 3 = modified_eocd
```

`modified_eocd` 是 EOCD 的副本，但其中的 Central Directory offset 字段会被改成 `APK Signing Block` 的起始偏移：

```text
EOCD.central_directory_offset = signing_block_offset
```

这样做的原因是：APK Signing Block 插入到了 Central Directory 前面。为了让 digest 表示“没有 Signing Block 时”的 ZIP 视图，需要把 EOCD 中的 Central Directory offset 调整回 Signing Block 起点。

## 10. Chunked Digest 计算

APK v2 内容 digest 使用 chunked digest。

每个 chunk 最大 1 MiB：

```text
chunk size = 1024 * 1024
```

先对每个 chunk 计算 digest。每个 chunk 的 digest 输入格式是：

```text
+-------------------------------+
| 0xa5                           |
+-------------------------------+
| chunk size, uint32 LE          |
+-------------------------------+
| chunk bytes                    |
+-------------------------------+
```

得到所有 chunk digest 后，再拼成最终 digest 输入：

```text
+-------------------------------+
| 0x5a                           |
+-------------------------------+
| chunk count, uint32 LE         |
+-------------------------------+
| digest of chunk 0              |
+-------------------------------+
| digest of chunk 1              |
+-------------------------------+
| ...                           |
+-------------------------------+
```

然后对这段数据再做一次 SHA-256 或 SHA-512，得到最终 APK content digest。

伪代码：

```text
chunk_digests = 0x5a || uint32_le(chunk_count)

for each chunk:
    chunk_input = 0xa5 || uint32_le(chunk_size) || chunk_bytes
    chunk_digest = hash(chunk_input)
    chunk_digests += chunk_digest

final_digest = hash(chunk_digests)
```

## 11. 验证流程总结

APK v2 基础验证可以概括为：

```text
1. 从 APK 末尾找到 ZIP EOCD
2. 从 EOCD 读取 Central Directory offset
3. 在 Central Directory 前找到 APK Signing Block
4. 在 APK Signing Block 中找到 ID 0x7109871a 的 v2 block
5. 解析 v2 block 中的 signer 列表
6. 对每个 signer：
   - 解析 signed data
   - 解析 signatures
   - 解析 public key
   - 使用 public key 验证 signed data 的签名
   - 检查 public key 是否等于第一张证书中的 public key
   - 读取 signed data 中声明的 APK content digest
7. 按 v2 chunked digest 规则重新计算 APK 内容 digest
8. 比较实际 digest 和 signer 中声明的 digest
```

只要签名验证失败、证书 public key 不匹配、digest 不一致、结构字段越界或缺失，APK v2 校验就应失败。

## 12. 本工具的外部证书校验策略

本目录中的 `apksig_v2_verify` 工具不是只验证“签名块自洽”，而是要求调用方提供外部证书：

```bash
apksig_v2_verify --apk signed.zip --cert release.x509.pem
```

工具会从 `release.x509.pem` 中提取 SubjectPublicKeyInfo DER public key，并要求：

```text
外部证书 public key
=
signer.public_key
=
signed_data.certificates[0].public key
```

然后工具使用外部证书 public key 验证 signer 的 `signed data` 签名。

这样做的意义是：

- 设备端不信任 APK 签名块里任意携带的证书。
- APK 必须由设备端指定的证书对应私钥签名。
- 签名块中的 signer public key 和内嵌第一张证书仍必须保持一致，防止结构拼接或伪造。

这个策略更适合“服务端制作签名包，设备端只做校验”的场景。

## 13. 服务端签名和设备端校验

### 13.1 生成私钥和证书

推荐使用 EC P-256 key。私钥只保存在服务端，证书可以放到设备端用于校验。

```bash
# 生成 EC 私钥，PEM 格式
openssl ecparam -name prime256v1 -genkey -noout -out release.key.pem

# 转成 PKCS#8 DER，无密码，供 apksigner --key 使用
openssl pkcs8 -topk8 -inform PEM -outform DER \
  -in release.key.pem \
  -out release.pk8 \
  -nocrypt

# 生成自签名 X.509 证书，PEM 格式
openssl req -new -x509 \
  -key release.key.pem \
  -out release.x509.pem \
  -days 3650 \
  -sha256 \
  -subj "/C=CN/ST=Test/L=Test/O=YourOrg/OU=Signing/CN=APK V2 Signing"
```

文件用途：

| 文件 | 用途 | 放置位置 |
| --- | --- | --- |
| `release.key.pem` | 原始 EC 私钥 | 服务端保存 |
| `release.pk8` | apksigner 使用的 PKCS#8 DER 私钥 | 服务端保存 |
| `release.x509.pem` | 包含 public key 的 X.509 证书 | 服务端和设备端 |

### 13.2 服务端使用 apksigner 制作签名包

```bash
java -jar apksigner.jar sign -verbose \
  --key release.pk8 \
  --cert release.x509.pem \
  --min-sdk-version 24 \
  --v1-signing-enabled false \
  --v2-signing-enabled true \
  --v3-signing-enabled false \
  --out signed.zip \
  unsigned.zip
```

说明：

- `--key release.pk8`：服务端私钥，用来生成签名。
- `--cert release.x509.pem`：证书会被写入 APK v2 signing block。
- `--v1-signing-enabled false`：关闭 JAR/v1 签名。
- `--v2-signing-enabled true`：开启 APK Signature Scheme v2。
- `--v3-signing-enabled false`：只生成 v2 签名块，避免额外写入 v3 block。

### 13.3 设备端使用 apksig_v2_verify 校验

长选项：

```bash
apksig_v2_verify \
  --apk signed.zip \
  --cert release.x509.pem
```

短选项：

```bash
apksig_v2_verify -a signed.zip -c release.x509.pem
```

位置参数：

```bash
apksig_v2_verify signed.zip release.x509.pem
```

成功时输出：

```text
APK Signature Scheme v2 verified
```

失败时输出：

```text
APK Signature Scheme v2 verification failed: ...
```

常见失败原因：

| 错误类型 | 含义 |
| --- | --- |
| `signer public key does not match trusted certificate` | APK 不是由输入证书对应私钥签名 |
| `signature over signed-data did not verify` | signer 签名数学验证失败 |
| `public key in signatures record does not match first certificate` | 签名块中 signer public key 和内嵌证书不一致 |
| `APK content digest mismatch` | APK 内容被修改或 digest 不匹配 |
| `APK Signature Scheme v2 block not found` | 文件没有 v2 签名块 |

## 14. 签名块中证书和外部证书的关系

使用如下命令签名时：

```bash
java -jar apksigner.jar sign \
  --key release.pk8 \
  --cert release.x509.pem \
  --v1-signing-enabled false \
  --v2-signing-enabled true \
  --v3-signing-enabled false \
  --out signed.zip \
  unsigned.zip
```

`signed.zip` 的 v2 signing block 中会包含：

```text
signer.public_key
signed_data.certificates[0]
```

其中：

- `signer.public_key` 是 SubjectPublicKeyInfo DER 编码的 public key。
- `signed_data.certificates[0]` 是 `release.x509.pem` 对应的 DER X.509 证书。
- `certificates[0]` 里面也包含同一个 public key。

本工具会同时检查签名块内部一致性和外部证书匹配：

```text
release.x509.pem public key
    |
    +-- must equal signer.public_key
    |
    +-- must equal signed_data.certificates[0].public key
```

如果攻击者重新生成一个签名块，并在里面放入自己的证书和 public key，签名块内部可能自洽，
但只要它不匹配设备端输入的 `release.x509.pem`，本工具就会拒绝。

## 15. 和 JAR/v1 签名的区别

APK v1 签名基于 JAR signing，主要保护 ZIP entry 的内容，但 ZIP 元数据和部分结构不在强保护范围内。

APK v2 是 whole-file signing。它从 APK 文件结构层面对内容、Central Directory 和 EOCD 进行 digest 保护，只排除 APK Signing Block 自身。因此 v2 可以检测更多针对 ZIP 结构的篡改。

简化对比：

| Scheme | 覆盖范围 | 特点 |
| --- | --- | --- |
| v1 / JAR | ZIP entries | 兼容老 Android，但保护范围较弱 |
| v2 | APK 文件主体、Central Directory、EOCD | whole-file signing，校验更强 |
