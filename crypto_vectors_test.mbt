///|
fn hex(s : String) -> Bytes {
  @hex.decode(s) catch {
    _ => abort("bad hex")
  }
}

///|
test "RFC 8032 Ed25519 test 1 empty message" {
  let seed = hex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let pk = @lib.ed25519_public_key(seed)
  assert_eq(
    @hex.encode(pk),
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  let sig = @lib.ed25519_sign(seed, b"")
  assert_eq(
    @hex.encode(sig),
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  )
  assert_true(@lib.ed25519_verify(pk, b"", sig))
}

///|
test "RFC 8032 Ed25519 test 2 one-byte message" {
  let seed = hex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let pk = @lib.ed25519_public_key(seed)
  assert_eq(
    @hex.encode(pk),
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  )
  let msg = hex("72")
  let sig = @lib.ed25519_sign(seed, msg)
  assert_eq(
    @hex.encode(sig),
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  )
  assert_true(@lib.ed25519_verify(pk, msg, sig))
  assert_false(@lib.ed25519_verify(pk, b"", sig))
}

///|
test "RFC 4231 HMAC-SHA256 cases 1 and 2" {
  let key1 = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let mac1 = @lib.hmac_sha256(key1, @utf8.encode("Hi There"))
  assert_eq(
    @hex.encode(mac1),
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  )
  let mac2 = @lib.hmac_sha256(
    @utf8.encode("Jefe"),
    @utf8.encode("what do ya want for nothing?"),
  )
  assert_eq(
    @hex.encode(mac2),
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  )
}

///|
test "RFC 6979 ECDSA P-256 SHA-256 raw r||s" {
  let d = hex(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let msg = @utf8.encode("sample")
  let sig = @lib.ecdsa_p256_sign(d, msg)
  assert_eq(
    @hex.encode(sig),
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
  )
  let pk = @lib.ecdsa_p256_public_key(d)
  assert_true(@lib.ecdsa_p256_verify(pk, msg, sig))
  assert_false(@lib.ecdsa_p256_verify(pk, @utf8.encode("test"), sig))
}

///|
test "NIST SP 800-38D AES-128-GCM and an AES-256-GCM round trip" {
  let key = hex("feffe9928665731c6d6a8f9467308308")
  let iv = hex("cafebabefacedbaddecaf888")
  let pt = hex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
  )
  let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let boxed = @lib.aes_gcm_encrypt(pt, key, iv, aad)
  assert_eq(
    @hex.encode(boxed.ct),
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
  )
  assert_eq(@hex.encode(boxed.tag), "5bc94fbc3221a5db94fae95ae7121a47")
  let opened = @lib.aes_gcm_decrypt(boxed.ct, key, iv, aad, boxed.tag)
  match opened {
    Ok(got) => assert_true(got == pt)
    Err(_) => abort("gcm decrypt failed")
  }
  let key256 = hex(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  let iv0 = hex("000000000000000000000000")
  let hello = @utf8.encode("hello")
  let boxed256 = @lib.aes_gcm_encrypt(hello, key256, iv0, b"")
  assert_eq(@hex.encode(boxed256.ct), "a6c22c5122")
  assert_eq(@hex.encode(boxed256.tag), "8b908f7f62ffcea6a92fabef39bf4d93")
}

///|
test "deterministic CBOR map used by COSE protected headers" {
  let encoded = @cbor.encode(
    @cbor.Map([
      (@cbor.Integer(4L), @cbor.Bytes(hex("3131"))),
      (@cbor.Integer(1L), @cbor.Integer(-7L)),
    ]),
  )
  assert_eq(@hex.encode(encoded), "a2012604423131")
}
