///|
test "RFC 4231 HMAC-SHA-384 and HMAC-SHA-512 case 1" {
  let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let msg = @utf8.encode("Hi There")
  assert_eq(
    @hex.encode(@lib.hmac_sha384(key, msg)),
    "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
  )
  assert_eq(
    @hex.encode(@lib.hmac_sha512(key, msg)),
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
  )
}

///|
test "COSE_Mac direct HMAC and COSE_Encrypt direct A128GCM" {
  let mac_key = @cose.CoseKey::Sym(
    @cose.SymKey::new(
      hex("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"),
    ),
  )
  let mac = @cose.Mac::decode(
    hex(
      "d8618540a1010554546869732069732074686520636f6e74656e742e582060cfe7d9c733a758e198ff758a381e43b3caf9867aebaef224ca8f11ffd3ac7a818340a20125044a6f75722d73656372657440",
    ),
  )
  mac.verify(hex("11aa22bb33cc44dd55006699"), mac_key)
  let enc_key = @cose.CoseKey::Sym(
    @cose.SymKey::new(hex("849b57219dae48de646d07dbb533566e")),
  )
  let enc = @cose.Encrypt::decode(
    hex(
      "d8608443a10101a1054c02d1f7e6f26c43d4868d87ce582460973a94bb2898009ee52ecfd9ab1dd25867374b7cde42d4f7e6dd896e231c71fdd6fc99818340a20125044a6f75722d73656372657440",
    ),
  )
  let pt = enc.decrypt(hex("0011bbcc22dd4455dd220099"), enc_key)
  assert_eq(@utf8.decode_lossy(pt), "This is the content.")
}

///|
test "HMAC-384, HMAC-256/64, A192GCM, ChaCha20-Poly1305 and AES-CCM-16-128/64" {
  let hs384 = @cose.Mac::decode(
    hex(
      "d8618543a10106a054546869732069732074686520636f6e74656e742e5830b3097f70009a11507409598a83e15bbbbf1982dce28e5ab6d5a6aff6897bd24bb8b7479622c9401b24090d458206d587818340a2012504467365632d343840",
    ),
  )
  hs384.verify(
    b"",
    @cose.CoseKey::Sym(
      @cose.SymKey::new(
        hex(
          "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c42718800112233778899aa2122232425262728",
        ),
      ),
    ),
  )
  let trunc = @cose.Mac0::decode(
    hex(
      "d18443a10104a054546869732069732074686520636f6e74656e742e4811f9e357975fb849",
    ),
  )
  trunc.verify(
    b"",
    @cose.CoseKey::Sym(
      @cose.SymKey::new(
        hex("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"),
      ),
    ),
  )
  let gcm192 = @cose.Encrypt0::decode(
    hex(
      "d08343a10102a1054c02d1f7e6f26c43d4868d87ce5824134d3b9223a00c1552c77585c157f467f295919d530fbe21f7689ab3cd4d18ffe8e17ceb",
    ),
  )
  let pt192 = gcm192.decrypt(
    b"",
    @cose.CoseKey::Sym(
      @cose.SymKey::new(hex("0f1e2d3c4b5a69788796a5b4c3d2e1f01f2e3d4c5b6a7988")),
    ),
  )
  assert_eq(@utf8.decode_lossy(pt192), "This is the content.")
  let chacha = @cose.Encrypt0::decode(
    hex(
      "d08344a1011818a1054c5c3a9950bd2852f66e6c8d4f5824ca119c45926da993d29b5d0cac9a84228c7668d492a1b9d7e32020ef21372e74def431b9",
    ),
  )
  let pt_chacha = chacha.decrypt(
    b"",
    @cose.CoseKey::Sym(
      @cose.SymKey::new(
        hex("0f1e2d3c4b5a69788796a5b4c3d2e1f01f2e3d4c5b6a798897a6b5c4d3e2f100"),
      ),
    ),
  )
  assert_eq(@utf8.decode_lossy(pt_chacha), "This is the content.")
  let ccm = @cose.Encrypt0::decode(
    hex(
      "d08343a1010aa1054d89f52f65a1c580933b5261a72f581c6899da0a132bd2d2b9b10915743ee1f7b92a4680e7c51bdbc1b320ea",
    ),
  )
  let pt_ccm = ccm.decrypt(
    b"",
    @cose.CoseKey::Sym(
      @cose.SymKey::new(hex("849b57219dae48de646d07dbb533566e")),
    ),
  )
  assert_eq(@utf8.decode_lossy(pt_ccm), "This is the content.")
}

///|
test "AES-128 key wrap opens an enveloped A128GCM message" {
  let msg = @cose.Encrypt::decode(
    hex(
      "d8608443a10101a1054cdddc08972df9be62855291a158246f5556d71834cd1bd3fdcbfff28cfa0f7d598c138d23b40c225af5e3f2096a46c766813d818340a20122044a6f75722d7365637265745818112872f405a5ac48a2ede46ac20e93e3d3a38b9762d0a3e8",
    ),
  )
  let pt = msg.decrypt(
    b"",
    @cose.CoseKey::Sym(
      @cose.SymKey::new(hex("849b57219dae48de646d07dbb533566e")),
    ),
  )
  assert_eq(@utf8.decode_lossy(pt), "This is the content.")
}

///|
test "partial IV is xored onto the right of Base IV" {
  let msg = @cose.Encrypt::decode(
    hex(
      "d8608443a10101a1064261a75824d3d893dff22bdcf09a58cbbe701371aee31ee0aa3c1c8a6ce8409d5e5e81a6b5c355a644818340a20125044a6f75722d73656372657440",
    ),
  )
  let key = @cose.CoseKey::Sym({
    ..@cose.SymKey::new(hex("849b57219dae48de646d07dbb533566e")),
    base_iv: Some(hex("89f52f65a1c5809300000000")),
  })
  let pt = msg.decrypt(b"", key)
  assert_eq(@utf8.decode_lossy(pt), "This is the content.")
}

///|
test "A128KW plus HMAC-512 verifies aes-wrap-128-03" {
  let msg = @cose.Mac::decode(
    hex(
      "d8618543a10107a054546869732069732074686520636f6e74656e742e58400021c21b2a7fadb677dab64389b3fda4aac892d5c81b786a459e4182104a1501462ffd471422af4d48beeb864951d5947a55e3155e670dfc4a96017b0fd0e725818340a20122044a6f75722d7365637265745848792c46ce0bc689747133fa0db1f5e2bc4daae22f906e93dfca2df44f0df6c2cef16ea8fc91d52ad662c4b49dd0d689e1086ec754347957f80f95c92c887521641b8f637d91c6e258",
    ),
  )
  msg.verify(
    b"",
    @cose.CoseKey::Sym(
      @cose.SymKey::new(hex("849b57219dae48de646d07dbb533566e")),
    ),
  )
}
