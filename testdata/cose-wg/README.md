# cose-wg/Examples

这些 JSON 来自 https://github.com/cose-wg/Examples ，以 Unlicense 贡献到公共领域。许可证全文见同目录 `UNLICENSE`。

`scripts/gen_vectors.py` 读取这里的文件，生成仓库根目录的 `vectors_gen_test.mbt`。测试执行 Sign1、Sign、Mac0、Mac、Encrypt0 和 Encrypt 中本库支持的算法。ECDH、HKDF 密钥派生和 AES-CBC-MAC 示例随目录保存时若未纳入生成表，则不计入通过数。
