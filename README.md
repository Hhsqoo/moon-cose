# moon-cose

[English] COSE (RFC 9052 / RFC 9053) signing and encryption for MoonBit: Sign1, Sign, Mac0, Encrypt0, and COSE_Key, on deterministic CBOR.

MoonBit 上的 COSE 签名与加密库。除 `COSE_Sign1`、`COSE_Mac0`、`COSE_Encrypt0` 外，还实现多名签名者的 `COSE_Sign`，以及带 direct / AES Key Wrap recipient 的 `COSE_Mac` 和 `COSE_Encrypt`。密码学调用 [mooncry](https://github.com/cc06b/mooncry)，CBOR 调用 [2515050242/cbor](https://github.com/2515050242/moonbit-cbor-RFC-8949-CBOR-Concise-Binary-Object-Representation)。

## 安装

工具链使用 MoonBit `0.10.19+97801ee1b`（见 `.moonbit-version`）。

```sh
curl -fsSL https://cli.moonbitlang.com/install/unix.sh | bash -s 0.10.19+97801ee1b
export PATH="$HOME/.moon/bin:$PATH"
git clone https://github.com/Hhsqoo/moon-cose
cd moon-cose
moon test --target native
moon run --target native cmd/main
```

依赖写在 `moon.mod`：`2515050242/cbor@0.1.2`、`cc06b/mooncry@0.95.0`。`moon test` 会自行下载。

## 快速开始

`cmd/main` 对一段 CBOR 负载做 EdDSA `COSE_Sign1` 签名并验签，再做 HMAC-256/256 的 Mac0 和 A256GCM 的 Encrypt0 往返。

库内签名一条文本：

```moonbit
let key = @cose.CoseKey::Okp(@cose.OkpKey::ed25519(public_key, Some(seed)))
let signed = @cose.Sign1::sign(
  @cose.Header::with_alg(@cose.EdDSA),
  @cose.Header::empty(),
  Some(payload),
  b"",
  key,
)
let bytes = signed.encode()
let decoded = @cose.Sign1::decode(bytes)
decoded.verify(b"", key)
```

`external_aad` 传给 `sign` / `verify` / `mac` / `encrypt` / `decrypt` 的最后一个字节串参数。空 AAD 用 `b""`。

## API

| 类型 | 作用 |
| --- | --- |
| `Header` / `Protected` | 未保护头图，以及 bstr 包裹的受保护头。验签使用原始 protected 字节，不重新编码。 |
| `CoseAlg` | `ES256`、`EdDSA`、`HMAC_256_256`、`A128GCM`、`A256GCM`，以及其它 int / text。 |
| `CoseKey` | `Okp`、`Ec2`、`Sym`。`encode` / `decode` 读写 COSE_Key。 |
| `Sign1` | `sign`、`encode`、`decode`、`verify`。标签 18，也接受无标签数组。 |
| `Sign` | 多名签名者。`verify_signer` 按序号验签。标签 98。 |
| `Mac0` | HMAC-256/256。标签 17。 |
| `Encrypt0` | A128GCM / A256GCM。密文为 `ciphertext \|\| 16 字节 tag`。标签 16。 |
| `sig_structure` / `mac_structure` / `enc_structure` | RFC 9052 的待签名、待 MAC、AEAD AAD 字节串。 |

错误类型 `CoseError`：

| 构造器 | 含义 |
| --- | --- |
| `BadStructure` | 数组长度、缺字段、IV 长度、重复 label、不理解的 crit |
| `UnsupportedAlg` | 算法或曲线不在本库范围内 |
| `AlgMismatch` | 头里的 alg 与密钥上的 alg，或 protected 与 unprotected 的 alg 不一致；密钥类型与算法不匹配 |
| `VerificationFailed` | 签名或 MAC 校验失败 |
| `DecryptionFailed` | GCM 标签校验失败 |
| `MalformedCbor` | CBOR 解码失败，含非规范整数编码 |

## 支持的算法与结构

| 结构 | 算法 | 标签 |
| --- | --- | --- |
| COSE_Sign1 | EdDSA (Ed25519, -8)、ES256 (-7) | 18 |
| COSE_Sign | 同上，可多名签名者 | 98 |
| COSE_Mac0 / COSE_Mac | HMAC 256/64 (4)、256/256 (5)、384/384 (6)、512/512 (7) | 17 / 97 |
| COSE_Encrypt0 / COSE_Encrypt | A128GCM (1)、A192GCM (2)、A256GCM (3)、ChaCha20/Poly1305 (24)、AES-CCM 八个参数组 (10–13、30–33) | 16 / 96 |
| recipient | direct (-6)、A128KW (-3)、A192KW (-4)、A256KW (-5) | 无 |
| COSE_Key | OKP (kty 1, Ed25519 crv 6)、EC2 (kty 2, P-256 crv 1)、Symmetric (kty 4)，含 Base IV | 无 |

头 label：alg (1)、crit (2)、content type (3)、kid (4)、IV (5)、partial IV (6)。`crit` 里出现 1–6 以外的 label 会拒绝。创建空 protected 头时编码为零长度 bstr（`h''`）；解码同时接受 `h''` 和 `h'a0'`。

ES256 签名是 RFC 9053 的 64 字节 `r || s`。本库签名使用 mooncry 的 RFC 6979 确定性 k；验签接受任意合法的 `r || s`，包括示例里的非确定性签名。

## 测试

`moon test --target native` 当前 26 项全部通过。其中一项遍历 123 条 cose-wg 向量。

| 目录 | 执行 | 验签/解密通过 | 失败向量被拒绝 | 不支持的算法被拒绝 | 与规范不一致的示例被拒绝 |
| --- | ---: | ---: | ---: | ---: | ---: |
| sign1-tests | 9 | 2 | 4 | 2 | 1 |
| sign-tests | 10 | 3 | 4 | 2 | 1 |
| eddsa-examples | 4 | 2 | 0 | 2 | 0 |
| ecdsa-examples | 8 | 2 | 0 | 6 | 0 |
| mac0-tests | 10 | 3 | 4 | 2 | 1 |
| mac-tests | 10 | 3 | 4 | 2 | 1 |
| hmac-examples | 10 | 8 | 2 | 0 | 0 |
| encrypted-tests | 10 | 3 | 4 | 2 | 1 |
| enveloped-tests | 10 | 3 | 4 | 2 | 1 |
| aes-gcm-examples | 9 | 7 | 2 | 0 | 0 |
| aes-ccm-examples | 16 | 16 | 0 | 0 | 0 |
| aes-wrap-examples | 15 | 9 | 0 | 6 | 0 |
| chacha-poly-examples | 2 | 2 | 0 | 0 | 0 |
| 合计 | 123 | 63 | 28 | 26 | 6 |

另外四项目录里还有 10 个 JSON（`hmac-examples` 的 COSE_Mac、`aes-gcm-examples` 的 enveloped）随仓库保存，不在上表中执行。

六条「与规范不一致」的示例是 `sign1-tests/sign-pass-01`、`sign-tests/sign-pass-01`、`mac0-tests/mac-pass-01`、`mac-tests/mac-pass-01`、`encrypted-tests/enc-pass-01`、`enveloped-tests/env-pass-01`。消息里的 protected 桶被改成了 `h'A0'`，但签名、MAC 或 GCM 是对零长度 protected bstr 计算的。按 RFC 9052，受保护头以原始字节进入结构，因此这些消息必须失败。测试断言库拒绝它们。

密码学自测（RFC 8032、RFC 4231、RFC 6979、NIST SP 800-38D）在 `crypto_vectors_test.mbt`。

## 结构

```
alg.mbt header.mbt structures.mbt   算法、头、Sig/MAC/Enc 结构
key.mbt                             COSE_Key
crypto_ops.mbt                      调用 mooncry 的签名、MAC、GCM
sign1.mbt sign.mbt mac0.mbt encrypt0.mbt
cmd/main                            可运行示例
testdata/cose-wg                    cose-wg/Examples
scripts/gen_vectors.py              由 JSON 生成 vectors_gen_test.mbt
```

验签路径读取消息里的 protected bstr，原样放进 `Sig_structure` / `MAC_structure` / `Enc_structure`，再交给 mooncry。AES-GCM 的 AAD 是 `Enc_structure` 的 CBOR，不是调用方的 `external_aad` 本身；`external_aad` 嵌在该结构里。

## 尚未覆盖

- ECDH-ES / ECDH-SS、HKDF 密钥派生、AES-CBC-MAC。mooncry 0.95.0 没有公开的 P-384、P-521 ECDSA，也没有单独的 P-256 ECDH 接口，因此 ES384、ES512 和 ECDH-ES + HKDF-256 未在本仓库实现
- 计数器签名、嵌套 recipient
- 非规范 CBOR（由所用 CBOR 库拒绝）
- `aes-gcm-05` 的消息只携带 partial IV。官方 JSON 的密钥没有 Base IV；测试用未发送的完整 IV 反推 Base IV `89F52F65A1C5809300000000`，再按右对齐异或还原 nonce

## 和 mooncred 的差别

检索时，最接近的已发布包是 [`moonbitstack/mooncred@0.6.7`](https://mooncakes.io/docs/moonbitstack/mooncred) 的 `cose` 子包（Apache-2.0）。它的文档写明覆盖 `COSE_Sign1`、`COSE_Mac0`、`COSE_Encrypt0` 和 CWT，并服务于 JWT / JWK / X.509。

| 能力 | moon-cose | mooncred `cose` |
| --- | --- | --- |
| COSE_Sign1 / Mac0 / Encrypt0 | 有 | 有 |
| 多名签名者的 COSE_Sign | 有 | 文档未列 |
| 带 recipient 的 COSE_Mac、COSE_Encrypt | 有，direct 与 A128/A192/A256KW | 文档未列 |
| COSE_Key（OKP / EC2 / Symmetric，含 Base IV） | 有 | 文档未列 |
| HMAC 256/64、384/384、512/512 | 有 | 未作为独立 COSE 算法表列出 |
| A192GCM、ChaCha20-Poly1305、AES-CCM 八个参数组 | 有 | 文档未列 |
| partial IV 与 Base IV 右对齐异或 | 有 | 文档未列 |
| CWT / JOSE | 无 | 有 |
| ECDH-ES + HKDF、ES384 / ES512 | 无。mooncry 0.95.0 没有公开的 P-384 / P-521 ECDSA，也没有可直接调用的 P-256 ECDH | 不在其 COSE 文档范围内 |

本库不实现 CWT。密码学与 CBOR 分别来自 mooncry 和 `2515050242/cbor`。

## 来源与许可证

本库 Apache-2.0。来源、许可证和移植范围见 [NOTICE](NOTICE) 与 [docs/source-attribution.md](docs/source-attribution.md)。
