# 来源与移植范围

## google/coset

- 仓库：https://github.com/google/coset
- 许可证：Apache-2.0
- 移植范围：COSE 头图、常见 label、`Sig_structure` / `MAC_structure` / `Enc_structure`，以及 `COSE_Sign1`、`COSE_Sign`、`COSE_Mac0`、`COSE_Mac`、`COSE_Encrypt0`、`COSE_Encrypt` 和 `COSE_recipient` 的 tagged / untagged 数组。direct 与 AES Key Wrap 的 recipient 语义按 RFC 9052 / RFC 9053，不复制 coset 源码。
- 未移植：coset 的 Rust API、计数器签名、recipient、与 `ciborium` 绑定的编解码实现。密码学原语不来自 coset。

## 2515050242/cbor

- 包：`2515050242/cbor@0.1.2`
- 仓库：https://github.com/2515050242/moonbit-cbor-RFC-8949-CBOR-Concise-Binary-Object-Representation
- 许可证：Apache-2.0
- 用途：全部 CBOR 编解码。map 按 RFC 8949 第 4.2 节做确定性排序，`Sig_structure` 依赖这一点。
- 选择原因：`mizchi/cbor@0.1.1`（MIT）在 MoonBit 0.10.19 上无法安装（`moon.mod.json` 已不受支持），且其 map 编码不排序键。本仓库没有再实现一份 CBOR 编解码器。
- 限制：该解码器拒绝非规范的整数和长度编码。cose-wg 示例使用规范编码；非规范的 COSE 消息会得到 `MalformedCbor`。

## cc06b/mooncry

- 包：`cc06b/mooncry@0.95.0`
- 仓库：https://github.com/cc06b/mooncry
- 许可证：Apache-2.0
- 用途：Ed25519、ECDSA P-256（SHA-256，原始 `r || s`）、HMAC-SHA-256/384/512、AES-GCM、AES-KW、AES-CCM、ChaCha20-Poly1305、HKDF-SHA-256（尚未接到 COSE KDF）。
- 本仓库没有重写这些原语。接入前用下列向量核对过 0.95.0：
  - RFC 8032 Ed25519 测试 1 和测试 2
  - RFC 4231 HMAC-SHA-256 用例 1 和 2，以及 HMAC-SHA-384 / HMAC-SHA-512 用例 1（与 Python hashlib 一致）
  - RFC 6979 A.2.5 ECDSA P-256 + SHA-256
  - NIST SP 800-38D AES-128-GCM，以及一组 AES-256-GCM
- 没有公开的 P-384 / P-521 ECDSA，也没有单独的 P-256 ECDH。因此 ES384、ES512 和 ECDH-ES + HKDF-256 未实现，而不是用错误的曲线冒充。
- `aes_gcm_*` 与 ChaCha20-Poly1305 只接受 12 字节 nonce。AES-CCM 的 nonce 长度按 RFC 9053：`AES-CCM-16-*` 为 13 字节，`AES-CCM-64-*` 为 7 字节。partial IV 与密钥的 Base IV 按右对齐异或。

## cose-wg/Examples

- 仓库：https://github.com/cose-wg/Examples
- 许可证：Unlicense（见 `testdata/cose-wg/UNLICENSE`）
- 用途：`testdata/cose-wg/` 下的 JSON 向量。`scripts/gen_vectors.py` 生成 `vectors_gen_test.mbt`。
- 执行范围：支持的结构（Sign1、Sign、Mac0、Encrypt0）里每条 JSON。`COSE_Mac` 与 `COSE_Encrypt`（带 recipient 的 enveloped）只随目录保存，不进入通过计数。
